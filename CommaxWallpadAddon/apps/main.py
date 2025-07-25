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

# --- (기존 TypedDict 및 데코레이터 코드는 그대로 유지) ---
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
# --- (여기까지는 기존 코드와 동일) ---


class WallpadController:
    def __init__(self, config: Dict[str, Any], logger: Logger) -> None:
        self.supervisor_api = SupervisorAPI()
        self.config: Dict[str, Any] = config
        self.logger: Logger = logger
        self.share_dir: str = '/share'
        
        # --- (설정 변수 초기화는 기존과 거의 동일) ---
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
        # writer를 클라이언트 종류별로 관리 (월패드, HA 등)
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
        # state_updater가 사용할 publish 함수를 self.publish_to_ha로 변경
        self.state_updater = StateUpdater(self.STATE_TOPIC, self.publish_to_ha) 
        self.is_available: bool = False

    # --- (load_devices_and_packets_structures, find_device, reboot_elfin_device, process_queue 등은 기존 코드와 동일) ---
    # (생략된 함수들은 기존 코드 그대로 사용하시면 됩니다. 아래에 변경된 함수들만 새로 추가/수정합니다.)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """개별 TCP 클라이언트 연결을 처리합니다. 클라이언트 종류를 식별합니다."""
        peername = writer.get_extra_info('peername')
        self.logger.info(f"새로운 클라이언트 연결: {peername}")
        client_type = 'unknown'

        try:
            # 첫 데이터 패킷으로 클라이언트 종류 식별 (예: 'iam_ha' 또는 월패드 데이터)
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
                # 첫 데이터도 처리
                await self.route_message(first_data, client_type)

            # 클라이언트로부터 계속 데이터 수신
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
            # 월패드에서 온 데이터 처리
            raw_data = data.hex().upper()
            self.logger.signal(f'->> [WALLPAD] 수신: {raw_data}')

            self.elfin_reboot_count = 0
            if not self.is_available:
                await self.publish_to_ha(f"{self.HA_TOPIC}/status", "online")
                self.is_available = True
            
            await self.message_processor.process_elfin_data(raw_data)
            self.COLLECTDATA['last_recv_time'] = time.time_ns()
            self.web_server.add_tcp_message(f"wallpad/recv", raw_data)

        elif source == 'ha':
            # HA에서 온 데이터(명령) 처리
            try:
                message = data.decode('utf-8')
                self.logger.debug(f'->> [HA] 수신: {message}')
                self.web_server.add_tcp_message("ha/command", message)
                
                # HAからのコマンドは 'topic:value' 形式と仮定
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
                # 웹서버 로그 추가
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
            # HA 클라이언트가 없을 경우를 대비해 로그만 남김
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
            raise  # 서버 시작 실패 시 애드온 종료

    async def main_loop(self) -> None:
        """메인 로직을 처리하는 루프 (기기 검색, 디스커버리, 큐 처리 등)."""
        self.logger.info("메인 루프 시작.")
        
        # 1. 기기 검색
        if not self.device_list:
            self.logger.info("저장된 기기 목록이 없습니다. 기기 검색을 시작합니다.")
            # 기기 검색을 위해 일정 시간 동안 데이터 수집 대기
            await asyncio.sleep(20) # 20초간 데이터 수집
            if not self.COLLECTDATA['recv_data']:
                 self.logger.warning("기기 검색 실패. 월패드로부터 받은 패킷이 없습니다.")
                 self.logger.warning("EW11 설정 및 월패드 연결을 확인해주세요.")
            else:
                 self.logger.info(f"{len(self.COLLECTDATA['recv_data'])}개의 패킷 수집 완료. 기기 분석 시작.")
                 self.device_list = self.find_device()

        # 2. HA에 디바이스 정보 전송 (Discovery)
        if self.device_list:
            self.logger.info("HA에 디바이스 정보를 게시합니다 (Discovery).")
            await self.discovery_publisher.publish_discovery_message()
        else:
            self.logger.warning("찾은 기기가 없어 HA Discovery를 건너뜁니다.")

        # 3. 큐 처리 및 모니터링 시작
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
                await asyncio.sleep(5) # 오류 발생 시 잠시 대기 후 재시도

    async def process_queue(self) -> None:
        """큐에 있는 명령을 처리합니다. publish_to_wallpad를 사용하도록 수정."""
        if not self.QUEUE:
            return
        
        send_data = self.QUEUE.pop(0)
        
        try:
            cmd_bytes = bytes.fromhex(send_data['sendcmd'])
            # 월패드로 직접 명령 전송
            await self.publish_to_wallpad(cmd_bytes)
            send_data['count'] += 1
        except (ValueError, TypeError) as e:
            self.logger.error(f"명령 전송 중 오류 발생 (잘못된 16진수 문자열): {str(e)}")
            return
        
        # --- (이하 응답 확인 로직은 기존과 동일) ---
        max_send_count = self.max_send_count
        expected_state = send_data.get('expected_state')
        if isinstance(expected_state, dict):
            # ... (기존 코드)
            pass # 이 부분은 수정하지 않음

        if send_data['count'] < max_send_count:
             # 재전송 로직
             self.QUEUE.insert(0, send_data)
        else:
            self.logger.warning(f"최대 전송 횟수 초과: {send_data['sendcmd']}")
        
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
            self.device_list = None # 초기화

        self.web_server.run()

        async def main():
            # TCP 서버 시작
            server_task = asyncio.create_task(self.start_tcp_server())
            
            # 메인 로직 루프 시작
            main_loop_task = asyncio.create_task(self.main_loop())
            
            # 두 태스크가 모두 완료될 때까지 실행
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

    # --- (기존 __del__ 함수는 그대로 유지) ---
    def __del__(self):
        """Clean up resources when class instance is deleted."""
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