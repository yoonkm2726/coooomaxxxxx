from gevent import monkey; monkey.patch_all()  # type: ignore

import time
import asyncio
import os
import socket
from .logger import Logger
from typing import Any, Dict, Union, List, Optional, Set, TypedDict, Callable, TypeVar, Callable
from functools import wraps
import yaml # type: ignore #PyYAML
import json
import re
import telnetlib3 # type: ignore
import shutil
from .web_server import WebServer
from .utils import byte_to_hex_str, checksum
from .supervisor_api import SupervisorAPI
from .message_processor import MessageProcessor
from .discovery_publisher import DiscoveryPublisher
from .state_updater import StateUpdater

T = TypeVar('T')

def require_device_structure(default_return: Any = None) -> Callable:
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
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
        self.ELFIN_TOPIC: str = config.get('elfin_TOPIC','ew11')
        self.HA_TOPIC: str = config.get('mqtt_TOPIC','commax')
        self.STATE_TOPIC: str = self.HA_TOPIC + '/{}/{}/state'
        self.TCP_HOST: str = self.config['tcp'].get('tcp_server') or "127.0.0.1"
        self.TCP_PORT: int = int(self.config['tcp'].get('tcp_port') or 1883)
        self.tcp_socket: Optional[socket.socket] = None
        self.QUEUE: List[QueueItem] = []
        self.max_send_count: int = self.config['command_settings'].get('max_send_count', 20)
        self.min_receive_count: int = self.config['command_settings'].get('min_receive_count', 3)
        self.COLLECTDATA: CollectData = {
            'send_data': [],
            'recv_data': [],
            'recent_recv_data': set(),
            'last_recv_time': time.time_ns()
        }
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
        self.state_updater = StateUpdater(self.STATE_TOPIC, self.send_tcp)
        self.is_available: bool = False

    def setup_tcp_socket(self) -> None:
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.connect((self.TCP_HOST, self.TCP_PORT))
            self.logger.info(f"TCP 소켓 연결 완료: {self.TCP_HOST}:{self.TCP_PORT}")
        except Exception as e:
            self.logger.error(f"TCP 소켓 연결 실패: {str(e)}")
            self.tcp_socket = None

    def send_tcp(self, data: bytes) -> None:
        if self.tcp_socket:
            try:
                self.tcp_socket.sendall(data)
                self.logger.debug(f"TCP 송신: {data.hex().upper()}")
            except Exception as e:
                self.logger.error(f"TCP 송신 오류: {str(e)}")
        else:
            self.logger.error("TCP 소켓이 연결되지 않았습니다.")

    def receive_tcp(self, bufsize: int = 1024) -> Optional[bytes]:
        if self.tcp_socket:
            try:
                data = self.tcp_socket.recv(bufsize)
                if data:
                    self.logger.debug(f"TCP 수신: {data.hex().upper()}")
                return data
            except Exception as e:
                self.logger.error(f"TCP 수신 오류: {str(e)}")
                return None
        else:
            self.logger.error("TCP 소켓이 연결되지 않았습니다.")
            return None

    def load_devices_and_packets_structures(self) -> None:
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
                    try:
                        os.makedirs(os.path.dirname(custom_file_path), exist_ok=True)
                        shutil.copy(default_file_path, custom_file_path)
                        with open(custom_file_path, 'r', encoding='utf-8') as file:
                            self.DEVICE_STRUCTURE = yaml.safe_load(file)
                        self.logger.info(f'기본 패킷 구조를 {custom_file_path}로 복사하고 로드했습니다.')
                    except Exception as e:
                        self.logger.error(f'기본 파일 복사 중 오류 발생: {str(e)}')
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

    @require_device_structure({})
    def find_device(self) -> Dict[str, Any]:
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
                            int(byte_to_hex_str(data_bytes[int(device_id_pos)]),16)
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
        max_send_count = self.max_send_count
        if not self.QUEUE:
            return
        send_data = self.QUEUE.pop(0)
        try:
            cmd_bytes = bytes.fromhex(send_data['sendcmd'])
            self.send_tcp(cmd_bytes)
            send_data['count'] += 1
        except (ValueError, TypeError) as e:
            self.logger.error(f"명령 전송 중 오류 발생: {str(e)}")
            return
        expected_state = send_data.get('expected_state')
        if (isinstance(expected_state, dict)):
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
        try:
            elfin_reboot_interval = self.config['elfin'].get('elfin_reboot_interval', 60)
            current_time = time.time_ns()
            last_recv = self.COLLECTDATA['last_recv_time']
            signal_interval = (current_time - last_recv)/1_000_000
            if signal_interval > elfin_reboot_interval * 1_000:
                self.logger.warning(f'{elfin_reboot_interval}초간 신호를 받지 못했습니다.')
                self.COLLECTDATA['last_recv_time'] = time.time_ns()
                self.elfin_reboot_count += 1
                if (self.config['elfin'].get("use_auto_reboot",True)):
                    self.logger.warning(f'EW11 재시작을 시도합니다. {self.elfin_reboot_count}')
                    await self.reboot_elfin_device()
            if (self.send_command_on_idle):
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
            self.setup_tcp_socket()
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            async def tcp_main_loop():
                no_recv_packet_count = 0
                queue_interval = self.config['command_settings'].get('queue_interval_in_second',0.01)
                while True:
                    try:
                        data = self.receive_tcp()
                        if data:
                            raw_data = data.hex().upper()
                            self.logger.signal(f'->> 수신: {raw_data}')
                            self.COLLECTDATA['recv_data'].append(raw_data)
                            self.COLLECTDATA['recent_recv_data'].add(raw_data)
                            self.COLLECTDATA['last_recv_time'] = time.time_ns()
                            self.web_server.add_mqtt_message("tcp/recv", raw_data)
                        await self.process_queue_and_monitor()
                        await asyncio.sleep(queue_interval)
                    except Exception as e:
                        self.logger.error(f"메인 루프 실행 중 오류 발생: {str(e)}")
                        await asyncio.sleep(1)
            self.loop.run_until_complete(tcp_main_loop())
        except Exception as e:
            self.logger.error(f"실행 중 오류 발생: {str(e)}")
            raise
        finally:
            if self.loop:
                self.loop.close()
            if self.tcp_socket:
                self.tcp_socket.close()

    def __del__(self):
        if hasattr(self, 'tcp_socket') and self.tcp_socket:
            self.tcp_socket.close()
        if self.loop and not self.loop.is_closed():
            self.loop.close()

if __name__ == '__main__':
    with open('/data/options.json') as file:
        CONFIG = json.load(file)
    logger = Logger(debug=CONFIG['log']['DEBUG'], elfin_log=CONFIG['log']['elfin_log'], mqtt_log=CONFIG['log']['mqtt_log'])
    logger.info("╔══════════════════════════════════════════╗")
    logger.info("║                                          ║")
    logger.info("║  Commax Wallpad Addon by ew11-tcp 시작   ║") 
    logger.info("║                                          ║")
    logger.info("╚══════════════════════════════════════════╝")
    controller = WallpadController(CONFIG, logger)
    controller.run()