from gevent import monkey; monkey.patch_all()  # type: ignore
import time
import asyncio
import os
import json
import yaml # type: ignore #PyYAML
import re
import telnetlib3 # type: ignore
import shutil
from .logger import Logger
from .web_server import WebServer
from .utils import byte_to_hex_str, checksum
from .supervisor_api import SupervisorAPI
from .message_processor import MessageProcessor
from .discovery_publisher import DiscoveryPublisher
from .state_updater import StateUpdater
from typing import Any, Dict, Union, List, Optional, Set, TypedDict, Callable, TypeVar

T = TypeVar('T')

def require_device_structure(default_return: Any = None) -> Callable:
    """DEVICE_STRUCTURE가 초기화되었는지 확인하는 데코레이터
    
    Args:
        default_return: DEVICE_STRUCTURE가 None일 때 반환할 기본값
        
    Returns:
        Callable: 데코레이터 함수
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        from functools import wraps
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.DEVICE_STRUCTURE is None:
                self.logger.error("DEVICE_STRUCTURE가 초기화되지 않았습니다.")
                return default_return
            return func(self, *args, **kwargs)
        return wrapper
    return decorator

class CollectData(TypedDict):
    send_data: List[str]
    recv_data: List[str]
    recent_recv_data: Set[str]
    last_recv_time: int

class ExpectedStatePacket(TypedDict):
    required_bytes: List[int]
    possible_values: List[List[str]]
    
class QueueItem(TypedDict):
    sendcmd: str
    count: int
    expected_state: Optional[ExpectedStatePacket]
    received_count: int

class WallpadController:
    def __init__(self, config: Dict[str, Any], logger: Logger) -> None:
        self.supervisor_api = SupervisorAPI()
        self.config: Dict[str, Any] = config
        self.logger: Logger = logger
        self.share_dir: str = '/share'
        self.ELFIN_TOPIC: str = config.get('elfin_TOPIC', 'ew11')
        self.HA_TOPIC: str = config.get('mqtt_TOPIC', 'commax')
        self.STATE_TOPIC: str = self.HA_TOPIC + '/{}/{}/state'
        self.TCP_HOST: str = self.config['tcp'].get('tcp_server') or os.getenv('TCP_HOST') or "0.0.0.0"
        self.TCP_PORT: int = int(self.config['tcp'].get('tcp_port') or os.getenv('TCP_PORT') or 1883)
        self.QUEUE: List[QueueItem] = []
        self.max_send_count: int = self.config['command_settings'].get('max_send_count', 20)
        self.min_receive_count: int = self.config['command_settings'].get('min_receive_count', 3)
        self.COLLECTDATA: CollectData = {
            'send_data': [],
            'recv_data': [],
            'recent_recv_data': set(),
            'last_recv_time': time.time_ns()
        }
        self.tcp_server: Optional[asyncio.Server] = None
        self.clients: Set[asyncio.StreamWriter] = set()
        self.device_list: Optional[Dict[str, Any]] = None
        self.DEVICE_STRUCTURE: Optional[Dict[str, Any]] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.load_devices_and_packets_structures()
        self.web_server = WebServer(self)
        self.elfin_reboot_count: int = 0
        self.elfin_unavailable_notification_enabled: bool = self.config['elfin'].get('elfin_unavailable_notification', False)
        self.send_command_on_idle: bool = self.config['command_settings'].get('send_command_on_idle', True)
        self.message_processor = MessageProcessor(self)
        self.discovery_publisher = DiscoveryPublisher(self)
        self.state_updater = StateUpdater(self.STATE_TOPIC, self.publish_tcp)
        self.is_available: bool = False

    def load_devices_and_packets_structures(self) -> None:
        """
        기기 및 패킷 구조를 로드하는 함수
        
        config의 vendor 설정에 따라 기본 구조 파일 또는 커스텀 구조 파일을 로드합니다.
        vendor가 설정되지 않은 경우 기본값으로 'commax'를 사용합니다.
        """
        try:
            vendor = self.config.get('vendor', 'commax').lower()
            if 'packet_file' in self.config:
                default_file_path = self.config['packet_file']
            else:
                default_file_path = f'/apps/packet_structures_commax.yaml'
                
            custom_file_path = f'/share/packet_structures_custom.yaml'

            if vendor == 'custom':
                try:
                    with open(custom_file_path, 'r', encoding='utf-8') as file:
                        self.DEVICE_STRUCTURE = yaml.safe_load(file)
                    self.logger.info(f'{vendor} 패킷 구조를 로드했습니다.')
                except FileNotFoundError:
                    self.logger.info(f'{custom_file_path} 파일이 없습니다. 기본 파일을 복사합니다.')
                    os.makedirs(os.path.dirname(custom_file_path), exist_ok=True)
                    shutil.copy(default_file_path, custom_file_path)
                    with open(custom_file_path, 'r', encoding='utf-8') as file:
                        self.DEVICE_STRUCTURE = yaml.safe_load(file)
                    self.logger.info(f'기본 패킷 구조를 {custom_file_path}로 복사하고 로드했습니다.')
            else:
                try:
                    with open(default_file_path, 'r', encoding='utf-8') as file:
                        self.DEVICE_STRUCTURE = yaml.safe_load(file)
                    self.logger.info(f'{vendor} 패킷 구조를 로드했습니다.')
                except FileNotFoundError:
                    self.logger.error(f'{vendor} 패킷 구조 파일을 찾을 수 없습니다.')
                    return

            if self.DEVICE_STRUCTURE is not None:
                for device_name, device in self.DEVICE_STRUCTURE.items():
                    for packet_type in ['command', 'state']:
                        if packet_type in device:
                            structure = device[packet_type]['structure']
                            field_positions = {}
                            for pos, field in structure.items():
                                field_name = field['name']
                                if field_name != 'empty':
                                    if field_name in field_positions:
                                        self.logger.error(
                                            f"중복된 필드 이름 발견: {device_name}.{packet_type} - "
                                            f"'{field_name}' (위치: {field_positions[field_name]}, {pos})"
                                        )
                                    else:
                                        field_positions[field_name] = pos
                            device[packet_type]['fieldPositions'] = field_positions
                        
        except FileNotFoundError:
            self.logger.error('기기 및 패킷 구조 파일을 찾을 수 없습니다.')
        except yaml.YAMLError:
            self.logger.error('기기 및 패킷 구조 파일의 YAML 형식이 잘못되었습니다.')

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle individual TCP client connections."""
        self.clients.add(writer)
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                self.handle_tcp_message(data, writer)
        except Exception as e:
            self.logger.error(f"TCP client handling error: {str(e)}")
        finally:
            self.clients.remove(writer)
            writer.close()
            await writer.wait_closed()

    def handle_tcp_message(self, data: bytes, writer: asyncio.StreamWriter) -> None:
        """Process incoming TCP messages."""
        try:
            topics = []
            if data.startswith(b'ew11/'):
                topics = data.decode().split('/')
            
            if topics and topics[0] == self.ELFIN_TOPIC:
                if topics[1] == 'recv':
                    self.elfin_reboot_count = 0
                    if not self.is_available:
                        self.publish_tcp(f"{self.HA_TOPIC}/status", "online".encode())
                        self.is_available = True
                    raw_data = data.hex().upper()
                    self.logger.signal(f'->> 수신: {raw_data}')
                    if self.loop and self.loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.message_processor.process_elfin_data(raw_data),
                            self.loop
                        )
                    current_time = time.time_ns()
                    self.COLLECTDATA['last_recv_time'] = current_time
                    self.web_server.add_tcp_message(data.decode(), raw_data)
                    
                elif topics[1] == 'send':
                    raw_data = data.hex().upper()
                    self.logger.signal(f'<<- 송신: {raw_data}')
                    self.COLLECTDATA['send_data'].append(raw_data)
                    if len(self.COLLECTDATA['send_data']) > 300:
                        self.COLLECTDATA['send_data'] = list(self.COLLECTDATA['send_data'])[-300:]
                    self.web_server.add_tcp_message(data.decode(), raw_data)
                    
            elif topics and topics[0] == self.HA_TOPIC:
                value = data.decode()
                self.logger.debug(f'->> 수신: {"/".join(topics)} -> {value}')
                self.web_server.add_tcp_message("/".join(topics), value)
                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.message_processor.process_ha_command(topics, value),
                        self.loop
                    )

        except Exception as err:
            self.logger.error(f'TCP message processing error: {str(err)}')

    async def publish_tcp(self, topic: str, value: Union[str, bytes], retain: bool = False) -> None:
        """Publish message to all connected TCP clients."""
        if isinstance(value, str):
            value = value.encode()
            
        for writer in self.clients:
            try:
                if topic.endswith('/send'):
                    writer.write(value)
                else:
                    writer.write(f"{topic}:{value.decode()}".encode())
                await writer.drain()
                self.logger.tcp(f'{topic} >> {value.decode()}')
            except Exception as e:
                self.logger.error(f"TCP publish error: {str(e)}")

    async def start_tcp_server(self) -> None:
        """Start the TCP server."""
        try:
            self.logger.info(f"Starting TCP server on {self.TCP_HOST}:{self.TCP_PORT}")
            self.tcp_server = await asyncio.start_server(
                self.handle_client, self.TCP_HOST, self.TCP_PORT
            )
            self.is_available = True
            await self.publish_tcp(f"{self.HA_TOPIC}/status", "online".encode(), retain=True)
        except Exception as e:
            self.logger.error(f"TCP server startup error: {str(e)}")
            self.is_available = False

    @require_device_structure({})
    def find_device(self) -> Dict[str, Any]:
        """Find devices from COLLECTDATA's recv_data."""
        try:
            if not os.path.exists(self.share_dir):
                os.makedirs(self.share_dir)
                self.logger.info(f'{self.share_dir} 디렉토리를 생성했습니다.')
            
            save_path = os.path.join(self.share_dir, 'commax_found_device.json')
            
            assert isinstance(self.DEVICE_STRUCTURE, dict), "DEVICE_STRUCTURE must be a dictionary"
            
            state_headers = {
                self.DEVICE_STRUCTURE[name]["state"]["header"]: name 
                for name in self.DEVICE_STRUCTURE 
                if "state" in self.DEVICE_STRUCTURE[name]
            }
            self.logger.info(f'검색 대상 기기 headers: {state_headers}')
            
            device_count = {name: 0 for name in state_headers.values()}
            
            collect_data_set = set(self.COLLECTDATA['recv_data'])
            for data in collect_data_set:
                data_bytes = bytes.fromhex(data)
                header = byte_to_hex_str(data_bytes[0])
                if data == checksum(data) and header in state_headers:
                    name = state_headers[header]
                    self.logger.debug(f'감지된 기기: {data} {name} ')
                    try:
                        device_id_pos = self.DEVICE_STRUCTURE[name]["state"]["fieldPositions"]["deviceId"]
                        device_count[name] = max(
                            device_count[name],
                            int(byte_to_hex_str(data_bytes[int(device_id_pos)]), 16)
                        )
                        self.logger.debug(f'기기 갯수 업데이트: {device_count[name]}')
                    except Exception as e:
                        self.logger.debug(f'deviceId가 없는 기기: {name} {e}')
                        device_count[name] = 1
            
            self.logger.info('기기 검색 종료. 다음의 기기들을 찾았습니다...')
            self.logger.info('======================================')
            
            device_list = {}
            for name, count in device_count.items():
                assert isinstance(self.DEVICE_STRUCTURE, dict)
                device_list[name] = {
                    "type": self.DEVICE_STRUCTURE[name]["type"],
                    "count": count
                }
                self.logger.info(f'DEVICE: {name} COUNT: {count}')
            
            self.logger.info('======================================')
            
            try:
                with open(save_path, 'w', encoding='utf-8') as make_file:
                    json.dump(device_list, make_file, indent="\t")
                    self.logger.info(f'기기리스트 저장 완료: {save_path}')
            except IOError as e:
                self.logger.error(f'기기리스트 저장 실패: {str(e)}')
            
            return device_list
            
        except Exception as e:
            self.logger.error(f'기기 검색 중 오류 발생: {str(e)}')
            return {}

    async def reboot_elfin_device(self):
        try:
            if self.elfin_reboot_count > 10 and self.is_available:
                await self.publish_tcp(f"{self.HA_TOPIC}/status", "offline".encode(), retain=True)
                self.is_available = False
            if self.elfin_unavailable_notification_enabled and self.elfin_reboot_count == 20:
                self.logger.error('EW11 응답 없음')
                self.supervisor_api.send_notification(
                    title='[Commax Wallpad Addon] EW11 점검 및 재시작 필요',
                    message=f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] EW11에서 응답이 없습니다. EW11 상태를 점검 후 애드온을 재시작 해주세요. 이 메시지를 확인했을 때 애드온이 다시 정상 작동 중이라면 무시해도 좋습니다.'
                )
                return

            try:
                async with asyncio.timeout(10):
                    reader, writer = await telnetlib3.open_connection(
                        self.config['elfin'].get('elfin_server'),
                        connect_minwait=0.1,
                        connect_maxwait=1.0
                    )
                    assert reader and writer
                    try:
                        await reader.readuntil(b"login: ")
                        writer.write(self.config['elfin'].get('elfin_id') + '\n')
                        await reader.readuntil(b"password: ")
                        writer.write(self.config['elfin'].get('elfin_password') + '\n')
                        writer.write('Restart\n')
                        await writer.drain()
                    except Exception as e:
                        self.logger.error(f'텔넷 통신 중 오류 발생: {str(e)}')
                    finally:
                        writer.close()
            except asyncio.TimeoutError:
                self.logger.error('텔넷 연결 시도 시간 초과')
            except Exception as e:
                self.logger.error(f'텔넷 연결 시도 중 오류 발생: {str(e)}')
            
            await asyncio.sleep(10)

        except Exception as err:
            self.logger.error(f'기기 재시작 프로세스 전체 오류: {str(err)}')

    async def process_queue(self) -> None:
        """Process all commands in the queue and check for expected responses."""
        max_send_count = self.max_send_count
        if not self.QUEUE:
            return
        
        send_data = self.QUEUE.pop(0)
        
        try:
            cmd_bytes = bytes.fromhex(send_data['sendcmd'])
            await self.publish_tcp(f'{self.ELFIN_TOPIC}/send', cmd_bytes)
            send_data['count'] += 1
        except (ValueError, TypeError) as e:
            self.logger.error(f"명령 전송 중 오류 발생: {str(e)}")
            return
            
        expected_state = send_data.get('expected_state')
        if isinstance(expected_state, dict):
            required_bytes = expected_state['required_bytes']
            possible_values = expected_state['possible_values']
            
            recv_data_set = self.COLLECTDATA['recent_recv_data']
            for received_packet in recv_data_set:
                if not isinstance(received_packet, str):
                    continue

                try:
                    received_bytes = bytes.fromhex(received_packet)
                except ValueError:
                    continue
                match = True
                try:
                    for pos in required_bytes:
                        if not isinstance(pos, int):
                            self.logger.error(f"패킷 비교 중 오류 발생: {pos}는 정수가 아닙니다.")
                            match = False
                            break
                        if len(received_bytes) <= pos:
                            self.logger.error(f"패킷 비교 중 오류 발생: {pos}는 바이트 배열의 길이보다 큽니다.")
                            match = False
                            break
                            
                        if possible_values[pos]:
                            if byte_to_hex_str(received_bytes[pos]) not in possible_values[pos]:
                                match = False
                                break
                            
                except (IndexError, TypeError) as e:
                    self.logger.error(f"패킷 비교 중 오류 발생: {str(e)}")
                    match = False
                    
                if match:
                    send_data['received_count'] += 1
                    self.COLLECTDATA['recent_recv_data'] = set()
                    self.logger.debug(f"예상된 응답을 수신했습니다 ({send_data['received_count']}/{self.min_receive_count}): {received_packet}")
                    
            if send_data['received_count'] >= self.min_receive_count:
                return
            
            if send_data['count'] < max_send_count:
                self.logger.debug(f"명령 재전송 예약 (시도 {send_data['count']}/{max_send_count}): {send_data['sendcmd']}")
                self.QUEUE.insert(0, send_data)
            else:
                self.logger.warning(f"최대 전송 횟수 초과. 응답을 받지 못했습니다: {send_data['sendcmd']}")
                    
        else:
            if send_data['count'] < max_send_count:
                self.logger.debug(f"명령 전송 (횟수 {send_data['count']}/{max_send_count}): {send_data['sendcmd']}")
                self.QUEUE.insert(0, send_data)
        
        await asyncio.sleep(0.05)

    async def process_queue_and_monitor(self) -> None:
        """Process message queue and monitor device status."""
        try:
            elfin_reboot_interval = self.config['elfin'].get('elfin_reboot_interval', 60)
            current_time = time.time_ns()
            last_recv = self.COLLECTDATA['last_recv_time']
            signal_interval = (current_time - last_recv)/1_000_000
            
            if signal_interval > elfin_reboot_interval * 1_000:
                self.logger.warning(f'{elfin_reboot_interval}초간 신호를 받지 못했습니다.')
                self.COLLECTDATA['last_recv_time'] = time.time_ns()
                self.elfin_reboot_count += 1
                if self.config['elfin'].get("use_auto_reboot", True):
                    self.logger.warning(f'EW11 재시작을 시도합니다. {self.elfin_reboot_count}')
                    await self.reboot_elfin_device()
            if self.send_command_on_idle:
                if signal_interval > 130:
                    await self.process_queue()
            else:
                await self.process_queue()
            return
            
        except Exception as err:
            self.logger.error(f'process_queue_and_monitor() 오류: {str(err)}')
            return

    def run(self) -> None:
        self.logger.info("저장된 기기정보가 있는지 확인합니다. (/share/commax_found_device.json)")
        try:
            with open(self.share_dir + '/commax_found_device.json') as file:
                self.device_list = json.load(file)
            if not self.device_list:
                self.logger.info('기기 목록이 비어있습니다. 메인 루프 시작 후 기기 찾기를 시도합니다.')
            else:
                self.logger.info(f'기기정보를 찾았습니다. \n{json.dumps(self.device_list, ensure_ascii=False, indent=4)}')
        except IOError:
            self.logger.info('저장된 기기 정보가 없습니다. 메인 루프 시작 후 기기 찾기를 시도합니다.')
            self.device_list = {}

        try:
            self.web_server.run()
            
            tcp_connected = asyncio.Event()
            device_search_done = asyncio.Event()
            discovery_done = asyncio.Event()
            
            if self.device_list:
                device_search_done.set()
                            
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            async def wait_for_tcp():
                no_recv_packet_count = 0
                queue_interval = self.config['command_settings'].get('queue_interval_in_second', 0.01)
                await self.start_tcp_server()
                tcp_connected.set()
                
                while True:
                    try:
                        await tcp_connected.wait()
                        self.logger.info("TCP server started. Beginning main loop.")
                        
                        while tcp_connected.is_set():
                            if not discovery_done.is_set() and device_search_done.is_set():
                                await self.discovery_publisher.publish_discovery_message()
                                discovery_done.set()
                            recv_data_len = len(self.COLLECTDATA['recv_data'])
                            if not device_search_done.is_set():
                                if recv_data_len == 0:
                                    no_recv_packet_count += 1
                                    if no_recv_packet_count > 20:
                                        self.logger.warning("기기 검색 실패. EW11로부터 받은 패킷이 없습니다.")
                                        self.logger.warning("혹시 EW11 설정이 올바른지 확인해 주세요.")
                                        device_search_done.set()
                                self.logger.info(f"기기 검색을 위해 데이터 모으는중... {recv_data_len}/80")
                            if recv_data_len >= 80 and not device_search_done.is_set():
                                if not self.device_list:
                                    self.logger.info("충분한 데이터가 수집되어 기기 검색을 시작합니다.")
                                    self.device_list = self.find_device()
                                    if self.device_list:
                                        await self.discovery_publisher.publish_discovery_message()
                                        discovery_done.set()
                                    else:
                                        self.logger.warning("기기를 찾지 못했습니다.")
                                    device_search_done.set()
                            
                            await self.process_queue_and_monitor()
                            await asyncio.sleep(queue_interval)
                            
                    except Exception as e:
                        self.logger.error(f"Main loop error: {str(e)}")
                        await asyncio.sleep(1)
            
            self.loop.run_until_complete(wait_for_tcp())
            
        except Exception as e:
            self.logger.error(f"실행 중 오류 발생: {str(e)}")
            raise
        finally:
            if self.loop:
                self.loop.close()
            if self.tcp_server:
                self.tcp_server.close()

    def __del__(self):
        """Clean up resources when class instance is deleted."""
        if self.tcp_server:
            self.tcp_server.close()
        if self.loop and not self.loop.is_closed():
            self.loop.close()

if __name__ == '__main__':
    with open('/data/options.json') as file:
        CONFIG = json.load(file)
    logger = Logger(
        debug=CONFIG['log']['DEBUG'],
        elfin_log=CONFIG['log']['elfin_log'],
        mqtt_log=CONFIG['log']['mqtt_log']
    )
    logger.info("╔══════════════════════════════════════════╗")
    logger.info("║                                          ║")
    logger.info("║  Commax Wallpad Addon by ew11-tcp 시작   ║")
    logger.info("║                                          ║")
    logger.info("╚══════════════════════════════════════════╝")
    controller = WallpadController(CONFIG, logger)
    controller.run()