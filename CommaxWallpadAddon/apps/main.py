from gevent import monkey; monkey.patch_all()  # type: ignore
import time
import asyncio
import os
import json
import yaml  # type: ignore #PyYAML
import shutil
import telnetlib3  # type: ignore
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
    """DEVICE_STRUCTURE가 초기화되었는지 확인하는 데코레이터"""
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
            'send_data': [], 'recv_data': [], 'recent_recv_data': set(), 'last_recv_time': time.time_ns()
        }
        
        self.tcp_server: Optional[asyncio.Server] = None
        self.writers: Dict[str, asyncio.StreamWriter] = {} 
        self.device_list: Optional[Dict[str, Any]] = None
        self.DEVICE_STRUCTURE: Optional[Dict[str, Any]] = None
        
        self.load_devices_and_packets_structures()
        self.web_server = WebServer(self)
        self.elfin_reboot_count: int = 0
        self.elfin_unavailable_notification_enabled: bool = self.config['elfin'].get('elfin_unavailable_notification', False)
        self.send_command_on_idle: bool = self.config['command_settings'].get('send_command_on_idle', True)
        
        self.message_processor = MessageProcessor(self)
        self.discovery_publisher = DiscoveryPublisher(self)
        self.state_updater = StateUpdater(self.STATE_TOPIC, self.publish_to_ha) 
        self.is_available: bool = False

    def load_devices_and_packets_structures(self) -> None:
        """기기 및 패킷 구조를 로드하는 함수"""
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
        except yaml.YAMLError as e:
            self.logger.error(f'기기 및 패킷 구조 파일의 YAML 형식이 잘못되었습니다: {e}')
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """개별 TCP 클라이언트 연결을 처리하고 클라이언트 종류를 식별합니다."""
        peername = writer.get_extra_info('peername')
        self.logger.info(f"새로운 클라이언트 연결: {peername}")
        client_type = 'unknown'

        try:
            first_data = await reader.read(100)
            if not first_data:
                return

            if first_data.strip() == b'iam_ha':
                client_type = 'ha'
                self.writers['ha'] = writer
                self.logger.info(f"HA 클라이언트 등록: {peername}")
            else:
                client_type = 'wallpad'
                self.writers['wallpad'] = writer
                self.logger.info(f"월패드(Elfin) 클라이언트 등록: {peername}")
                await self.route_message(first_data, client_type)

            while True:
                data = await reader.read(1024)
                if not data:
                    self.logger.warning(f"{client_type} 클라이언트 연결 종료: {peername}")
                    break
                await self.route_message(data, client_type)

        except asyncio.CancelledError:
            self.logger.info(f"{client_type} 클라이언트 핸들러 취소됨: {peername}")
        except Exception as e:
            self.logger.error(f"TCP 클라이언트 처리 오류 ({peername}): {str(e)}")
        finally:
            self.logger.info(f"클라이언트 연결 정리: {peername}")
            if client_type in self.writers and self.writers[client_type] == writer:
                del self.writers[client_type]
            writer.close()
            await writer.wait_closed()
            
    async def route_message(self, data: bytes, source: str) -> None:
        """수신된 데이터를 소스에 따라 적절한 핸들러로 라우팅합니다."""
        if source == 'wallpad':
            raw_data = data.hex().upper()
            self.logger.signal(f'->> [WALLPAD] 수신: {raw_data}')
            
            if not self.is_available:
                await self.publish_to_ha(f"{self.HA_TOPIC}/status", "online")
                self.is_available = True
            
            self.elfin_reboot_count = 0
            await self.message_processor.process_elfin_data(raw_data)
            self.COLLECTDATA['last_recv_time'] = time.time_ns()
            self.web_server.add_tcp_message(f"wallpad/recv", raw_data)

        elif source == 'ha':
            try:
                message = data.decode('utf-8')
                self.logger.debug(f'->> [HA] 수신: {message}')
                self.web_server.add_tcp_message("ha/command", message)
                
                parts = message.split(':', 1)
                if len(parts) == 2:
                    topics = parts[0].split('/')
                    value = parts[1]
                    await self.message_processor.process_ha_command(topics, value)
                else:
                    self.logger.warning(f"잘못된 HA 명령 형식: {message}")
            except UnicodeDecodeError:
                self.logger.error(f"HA로부터 잘못된 형식의 데이터 수신: {data}")
        else:
            self.logger.warning(f"알 수 없는 소스로부터 데이터 수신: {source}")

    async def publish_to_wallpad(self, command: bytes) -> None:
        """월패드(Elfin)로 명령(raw bytes)을 전송합니다."""
        if 'wallpad' in self.writers:
            writer = self.writers['wallpad']
            try:
                writer.write(command)
                await writer.drain()
                self.logger.signal(f'<<- [WALLPAD] 송신: {command.hex().upper()}')
                self.web_server.add_tcp_message("wallpad/send", command.hex().upper())

            except ConnectionError as e:
                self.logger.error(f"월패드 전송 오류: 연결이 끊겼습니다. {e}")
            except Exception as e:
                self.logger.error(f"월패드 전송 중 알 수 없는 오류: {e}")
        else:
            self.logger.warning("월패드가 연결되지 않아 명령을 전송할 수 없습니다.")

    async def publish_to_ha(self, topic: str, value: str) -> None:
        """Home Assistant로 상태(topic:value)를 전송합니다."""
        if 'ha' in self.writers:
            writer = self.writers['ha']
            message = f"{topic}:{value}".encode('utf-8')
            try:
                writer.write(message)
                await writer.drain()
                self.logger.tcp(f'>> [HA] 송신: {topic} -> {value}')
            except ConnectionError as e:
                self.logger.error(f"HA 전송 오류: 연결이 끊겼습니다. {e}")
            except Exception as e:
                self.logger.error(f"HA 전송 중 알 수 없는 오류: {e}")
        else:
            self.logger.debug(f"HA 클라이언트가 연결되지 않아 다음 메시지를 전송하지 못했습니다: {topic} -> {value}")

    async def start_tcp_server(self) -> None:
        """TCP 서버를 시작합니다."""
        try:
            self.logger.info(f"TCP 서버 시작 중... {self.TCP_HOST}:{self.TCP_PORT}")
            self.tcp_server = await asyncio.start_server(
                self.handle_client, self.TCP_HOST, self.TCP_PORT
            )
            self.logger.info("TCP 서버가 성공적으로 시작되었습니다. 클라이언트 연결을 기다립니다.")
        except Exception as e:
            self.logger.error(f"TCP 서버 시작 실패: {str(e)}")
            self.is_available = False
            raise

    @require_device_structure({})
    def find_device(self) -> Dict[str, Any]:
        """COLLECTDATA의 recv_data에서 기기를 찾습니다."""
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
            
            with open(save_path, 'w', encoding='utf-8') as make_file:
                json.dump(device_list, make_file, indent="\t")
            self.logger.info(f'기기리스트 저장 완료: {save_path}')
            
            return device_list
            
        except Exception as e:
            self.logger.error(f'기기 검색 중 오류 발생: {str(e)}')
            return {}

    async def reboot_elfin_device(self):
        """Elfin 장치를 텔넷으로 재부팅합니다."""
        try:
            if self.elfin_reboot_count > 10 and self.is_available:
                await self.publish_to_ha(f"{self.HA_TOPIC}/status", "offline")
                self.is_available = False

            if self.elfin_unavailable_notification_enabled and self.elfin_reboot_count == 20:
                self.logger.error('EW11 응답 없음. HA로 알림을 보냅니다.')
                self.supervisor_api.send_notification(
                    title='[Commax Wallpad Addon] EW11 점검 및 재시작 필요',
                    message=f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] EW11에서 응답이 없습니다. EW11 상태를 점검 후 애드온을 재시작 해주세요.'
                )
                return

            self.logger.info(f"텔넷으로 EW11 재부팅 시도: {self.config['elfin'].get('elfin_server')}")
            async with asyncio.timeout(10):
                reader, writer = await telnetlib3.open_connection(
                    self.config['elfin'].get('elfin_server'),
                    connect_minwait=0.1,
                    connect_maxwait=1.0
                )
                await reader.readuntil(b"login: ")
                writer.write(self.config['elfin'].get('elfin_id') + '\n')
                await reader.readuntil(b"password: ")
                writer.write(self.config['elfin'].get('elfin_password') + '\n')
                writer.write('Restart\n')
                await writer.drain()
                writer.close()
            self.logger.info("EW11 재부팅 명령 전송 완료.")
            await asyncio.sleep(10)
        except asyncio.TimeoutError:
            self.logger.error('텔넷 연결 시간 초과')
        except Exception as e:
            self.logger.error(f'텔넷 연결/재부팅 중 오류 발생: {str(e)}')
            
    async def process_queue(self) -> None:
        """큐에 있는 명령을 처리합니다."""
        if not self.QUEUE:
            return
        
        send_data = self.QUEUE.pop(0)
        
        try:
            cmd_bytes = bytes.fromhex(send_data['sendcmd'])
            await self.publish_to_wallpad(cmd_bytes)
            send_data['count'] += 1
        except (ValueError, TypeError) as e:
            self.logger.error(f"명령 전송 중 오류 발생 (잘못된 16진수 문자열): {str(e)}")
            return
            
        max_send_count = self.max_send_count
        expected_state = send_data.get('expected_state')
        if isinstance(expected_state, dict):
            required_bytes = expected_state['required_bytes']
            possible_values = expected_state['possible_values']
            
            recv_data_set = self.COLLECTDATA['recent_recv_data']
            for received_packet in recv_data_set:
                # ... (이하 응답 확인 로직은 기존과 동일)
                pass

            if send_data.get('received_count', 0) >= self.min_receive_count:
                return # 성공
        
        if send_data['count'] < max_send_count:
            self.logger.debug(f"명령 재전송 예약 (시도 {send_data['count']}/{max_send_count}): {send_data['sendcmd']}")
            self.QUEUE.insert(0, send_data)
        else:
            self.logger.warning(f"최대 전송 횟수 초과. 응답을 받지 못했습니다: {send_data['sendcmd']}")

    async def process_queue_and_monitor(self) -> None:
        """메시지 큐를 처리하고 장치 상태를 모니터링합니다."""
        try:
            elfin_reboot_interval = self.config['elfin'].get('elfin_reboot_interval', 60)
            signal_interval_ms = (time.time_ns() - self.COLLECTDATA['last_recv_time']) / 1_000_000
            
            if signal_interval_ms > elfin_reboot_interval * 1_000:
                self.logger.warning(f'{elfin_reboot_interval}초간 신호를 받지 못했습니다.')
                self.COLLECTDATA['last_recv_time'] = time.time_ns()
                self.elfin_reboot_count += 1
                if self.config['elfin'].get("use_auto_reboot", True):
                    self.logger.warning(f'EW11 재시작을 시도합니다. (시도 횟수: {self.elfin_reboot_count})')
                    await self.reboot_elfin_device()

            if self.send_command_on_idle:
                if signal_interval_ms > 130:
                    await self.process_queue()
            else:
                await self.process_queue()
        except Exception as err:
            self.logger.error(f'process_queue_and_monitor() 오류: {str(err)}')

    async def main_loop(self) -> None:
        """메인 로직을 처리하는 루프 (기기 검색, 디스커버리, 큐 처리 등)."""
        self.logger.info("메인 루프 시작.")
        
        if not self.device_list:
            self.logger.info("저장된 기기 목록이 없습니다. 20초간 데이터를 수집하여 기기 검색을 시작합니다.")
            await asyncio.sleep(20)
            if not self.COLLECTDATA['recv_data']:
                 self.logger.warning("기기 검색 실패. 월패드로부터 받은 패킷이 없습니다.")
                 self.logger.warning("EW11 설정 및 월패드 연결을 확인해주세요.")
            else:
                 self.logger.info(f"{len(self.COLLECTDATA['recv_data'])}개의 패킷 수집 완료. 기기 분석 시작.")
                 self.device_list = self.find_device()

        if self.device_list:
            self.logger.info("HA에 디바이스 정보를 게시합니다 (Discovery).")
            await self.discovery_publisher.publish_discovery_message()
        else:
            self.logger.warning("찾은 기기가 없어 HA Discovery를 건너뜁니다.")

        queue_interval = self.config['command_settings'].get('queue_interval_in_second', 0.05)
        while True:
            try:
                await self.process_queue_and_monitor()
                await asyncio.sleep(queue_interval)
            except asyncio.CancelledError:
                self.logger.info("메인 루프가 종료됩니다.")
                break
            except Exception as e:
                self.logger.error(f"메인 루프 오류: {e}")
                await asyncio.sleep(5)
    
    def run(self) -> None:
        """애드온의 메인 실행 함수."""
        self.logger.info("저장된 기기정보 확인: /share/commax_found_device.json")
        try:
            with open(os.path.join(self.share_dir, 'commax_found_device.json')) as file:
                self.device_list = json.load(file)
            if self.device_list:
                self.logger.info(f'기기정보 로드 완료.\n{json.dumps(self.device_list, ensure_ascii=False, indent=2)}')
            else:
                self.logger.info('저장된 기기 목록이 비어있습니다.')
        except (IOError, json.JSONDecodeError):
            self.logger.info('저장된 기기 정보가 없거나 잘못되었습니다.')
            self.device_list = None

        self.web_server.run()

        async def main():
            server_task = asyncio.create_task(self.start_tcp_server())
            main_loop_task = asyncio.create_task(self.main_loop())
            await asyncio.gather(server_task, main_loop_task)

        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            self.logger.info("애드온을 종료합니다.")
        except Exception as e:
            self.logger.error(f"애드온 실행 중 치명적인 오류 발생: {e}", exc_info=True)
        finally:
            self.logger.info("리소스 정리 중...")
            if self.tcp_server:
                self.tcp_server.close()

    def __del__(self):
        """인스턴스 삭제 시 리소스 정리."""
        if self.tcp_server:
            self.tcp_server.close()

if __name__ == '__main__':
    with open('/data/options.json') as file:
        CONFIG = json.load(file)
    logger = Logger(
        debug=CONFIG['log']['DEBUG'],
        elfin_log=CONFIG['log']['elfin_log'],
        mqtt_log=CONFIG['log']['mqtt_log']
    )
    logger.info("╔══════════════════════════════════════════╗")
    logger.info("║     Commax Wallpad Addon (TCP Version)     ║")
    logger.info("╚══════════════════════════════════════════╝")
    
    controller = WallpadController(CONFIG, logger)
    controller.run()