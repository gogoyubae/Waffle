
import os
from threading import TIMEOUT_MAX
from tkinter.messagebox import NO
# from turtle import st

from config import *
from collections.abc import Callable

import struct
from typing import Tuple, Any

from time import time
from time import sleep

from tkinter import END


UDP_WINDOW_SIZE = 100
UDP_MAX_ACK_NUM = int(2**16)
UDP_TIMEOUT = 5
UDP_WAIT = 0.05

# 패킷 유형들 정의
PACKET_TYPE_FILE_START = b'\x00'
PACKET_TYPE_FILE_DATA = b'\x01'
PACKET_TYPE_FILE_END = b'\x02'
PACKET_TYPE_FILE_ACK = b'\x03'      # ACK도 패킷인가?!?!?!?!?!? ACK도 패킷이야!!!!!!!!

TCP_FILE_TRANSFER_END = PACKET_TYPE_FILE_END + bytes(PACKET_SIZE-1) # TCP에서의 파일 전송 종료를 알리기 위한 패킷


class FileTransfer:
    def __init__(self) -> None:
        self.file_name = None
        self.file_pointer = None
        
        # Receiver
        self.file_packet_start = 0  # 마지막으로 수신한 seq num. udp_recv_flag 길이 안에서 돌아야 함
        self.udp_recv_packet = [bytes(PACKET_SIZE) for _ in range(UDP_MAX_ACK_NUM)]     # reveicer측의 buffer인 듯. 최대 ack 개수개의 요소를 다 1024로 채워 놓음.
        self.udp_recv_flag = [False for _ in range(UDP_MAX_ACK_NUM)]    # 패킷 수신 여부 기록. 이것도 최대 ack 개수만큼 False로 채워 넣음
        # 위에 두 개는, list의 길이가 UDP_MAX_ACK_NUM만큼 있어서, ack num 자리에 필요한 걸 넣을 수 있음
        
        # Sender
        self.udp_send_packet = dict()   # Key: packet number / Value: 전송한 time, packet
        self.udp_ack_windows = [False for _ in range(UDP_MAX_ACK_NUM)]
        self.udp_ack_num = 0        # send_base
        self.udp_last_ack_num = 0   # next seq num
        # receiver에서 self.udp_last_ack_num를 업데이트 해주고, sender에서 self.udp_last_ack_num를 보는 건가..? 이게 ACK를 받는 건가!!
        
    # ==================== TCP ==================== #

    @staticmethod
    def tcp_packet_pack(packet_type: bytes, data: bytes) -> bytes:
        data_len = len(data)
        packet = packet_type + struct.pack(">H", data_len) + data
        packet = packet + bytes(PACKET_SIZE - len(packet)) # packet 크기 맞추기
        return packet
    
    @staticmethod
    def tcp_packet_unpack(packet: bytes) -> Tuple[bytes, bytes]:
        packet_type = packet[:1]
        data_len = struct.unpack(">H", packet[1:3])[0]
        data = packet[3:3+data_len]
        return packet_type, data

    def tcp_file_name_packet(self, file_name: str) -> bytes:
        # TCP 통신에서의 file 이름 전송용 패킷 생성 
        # 패킷 구조: \x00 + (이름 data 크기) + (파일 이름 data)
        data = file_name.encode(ENCODING)
        return self.tcp_packet_pack(PACKET_TYPE_FILE_START, data)

    def tcp_file_data_packet(self) -> Tuple[bool, bytes]:
        # tcp sener가 가진 self.file_pointer에서
        # 전송을 위한 packet을 생성한다,
        # 결과값: 패킷이 존재 여부, 생성된 패킷
        # 패킷 구조: \x01 + (data 크기) + (file data)
        data = self.file_pointer.read(PACKET_SIZE -1 -2)    # 전체 패킷 사이즈에서 1byte(packet_type), 2byte(data_len)를 제외한 나머지가 data
        if data:
            return True, self.tcp_packet_pack(PACKET_TYPE_FILE_DATA, data)
        else:
            return False, None
    
    def tcp_file_name_transfer(self, filename: str, tcp_send_func: Callable)-> None:
        # TCP 통신에서 sender에게 파일 전송이 시작을 알리면서 파일 이름을 전송한다.
        packet = self.tcp_file_name_packet(filename)
        tcp_send_func(packet)

    def tcp_file_send(self, filename: str, tcp_send_func: Callable)-> None:
        basename = os.path.basename(filename)   # 파일 경로에서 파일 이름만 반환
        self.file_pointer = open(filename, "rb")

        # packet의 파일 이름(basename)을 전송한다.
        self.tcp_file_name_transfer(basename, tcp_send_func)
        # print("S -- 이름 전송 종료")

        # 파일을 구성하는 data를 전송한다.
        # tcp_file_data_packet이 생성하는 packet을 tcp를 이용해 전부 전송한다.
        while True:
            flag, packet = self.tcp_file_data_packet()
            if not flag:
                break
            tcp_send_func(packet)
            # self.file_pointer.seek(PACKET_SIZE -1 -2)
        

        # TCP_FILE_TRANSFER_END을 전송하여 
        # 파일의 전송이 끝냈음을 알린다.
        tcp_send_func(TCP_FILE_TRANSFER_END)    # TCP_FILE_TRANSFER_END 이거 자체가 패킷인듯
        # TCP_FILE_TRANSFER_END을 전송 종료
        # print("S -- 파일 data 전송 종료")

        # 파일 닫기
        self.file_pointer.close()
        self.file_pointer = None
            
    def tcp_file_receive(self, packet) -> int:
        packet_type, data = self.tcp_packet_unpack(packet)
        
        if packet_type == PACKET_TYPE_FILE_START:
            # print("R -- 파일 이름 패킷 수신")
            basename = data.decode(ENCODING)
            self.file_name = basename
            file_path = './downloads/(tcp) '+basename
            # 파일의 이름을 받아 file_path 위치에 self.file_pointer를 생성한다.
            self.file_pointer = open(file_path, "wb")
            # print("R -- 파일 포인터 생성")
            return 0

        elif packet_type == PACKET_TYPE_FILE_DATA:
            # print("R -- 파일 데이터 패킷 수신")
            # self.file_pointer에 전송 받은 data를 저장한다.
            self.file_pointer.write(data)
            return 1
            
        elif packet_type == PACKET_TYPE_FILE_END:
            # 파일 전송이 끝난 것을 확인하고 file_pointer를 종료한다.
            self.file_pointer.close()
            self.file_pointer = None
            # print("R -- 파일 데이터 패킷 수신 완료")
            return 2
    
    # ==================== UDP ==================== #
    # udp_send_func == udp_file_transfer_send() 임!
    
    @staticmethod
    def udp_packet_pack(packet_type: bytes, ack_num: Any, data: bytes) -> bytes:
        '''mak_pkt : 전송할 데이터를 패킷으로 변환'''
        data_len = len(data)
        if type(ack_num) == int:
            packet = packet_type + struct.pack(">HH", ack_num, data_len) + data
        elif type(ack_num) == bytes:
            packet = packet_type + ack_num + struct.pack(">H", data_len) + data
        packet = packet + bytes(PACKET_SIZE - len(packet)) # packet 크기 맞추기
        return packet
    
    @staticmethod
    def udp_packet_unpack(packet: bytes) -> Tuple[bytes, int, bytes]:
        '''수신한 패킷을 데이터로 변환'''
        packet_type = packet[:1]                                # packet의 0번은 1byte packet_type
        ack_num, data_len = struct.unpack(">HH", packet[1:5])   # 1,2는 2byte ack_num, 3,4는 2byte data_len인듯
        data = packet[5:5+data_len]                             # 이후 byte들은 data에 넣음
        return packet_type, ack_num, data

    @staticmethod
    def udp_ack_bytes(packet: bytes) -> bytes:
        '''수신한 패킷에서 ack num 반환'''
        return packet[1:3]  # ACK number 반환
    
    def udp_file_data(self) -> Tuple[bool, bytes]:
        # udp sener가 전송할 file data를 얻는다
        # 결과값: file data
        data = self.file_pointer.read(PACKET_SIZE -1 -2 -2) # 전체 패킷 사이즈에서 1byte(packet_type), 2byte(ack_num), 2byte(data_len)를 제외한 나머지가 data
        if data:
            return True, data
        else:
            return False, None

    def udp_file_name_transfer(self, file_name: str, udp_send_func: Callable)-> None:
        data = file_name.encode(ENCODING)
        self.udp_send_with_record(PACKET_TYPE_FILE_START, data, udp_send_func)

    def udp_send_with_record(self, packet_type: bytes, data: bytes, udp_send_func: Callable) -> None:
        packet = self.udp_packet_pack(packet_type, self.udp_last_ack_num, data)
        udp_send_func(packet)
        # GBN, SR을 통한 재전송을 위해 packet과 전송 시간을 self.udp_send_packet에 저장한다.
        # 또한 self.udp_lask_ack_num을 update하여 새로 전송할 packet의 ack_num을 update한다.
        self.udp_send_packet[self.udp_last_ack_num] = (time(), packet)  # timer도 설정됨
        self.udp_last_ack_num = (self.udp_last_ack_num + 1) % UDP_MAX_ACK_NUM   # nextseqnum 업데이트

    def udp_file_send(self, filename: str, udp_send_func: Callable) -> None:
        basename = os.path.basename(filename)
        self.file_pointer = open(filename, "rb")
        # udp를 통해 파일의 basename을 전송하고 ack를 기다린다.
        # hint : self.udp_file_name_transfer 함수를 활용할 것
        self.udp_file_name_transfer(basename, udp_send_func)    # basename 전송
        # print("S -- 이름 전송")
        self.udp_gbn(udp_send_func)                        # ack 기다리면서 타임아웃되면 재전송하는 함수
        # print('S -- 이름송신종료')
        
        data_ready, data = self.udp_file_data()
        while data_ready:
            if len(self.udp_send_packet) < UDP_WINDOW_SIZE: #window의 크기보다 전송한 패킷의 양의 적은 경우
                self.udp_send_with_record(PACKET_TYPE_FILE_DATA, data, udp_send_func)
                # print(f"S -- 파일 데이터 패킷 {self.udp_last_ack_num} 송신")
                data_ready, data = self.udp_file_data() # 다음 전송할 data를 준비한다.

            else:
                # Window 사이즈보다 많이 전송할 순 없으니, 일단 ack를 기다림
                # PIPELINE을 위한 window를 전체를 사용하여 ack를 기다리며 timeout에 대처한다.
                # Timeout이 아닌 경우에는 Sleep(UDP_WAIT)를 사용한다.
                self.udp_gbn(udp_send_func)
                pass
        # 모든 파일 data의 ack를 기다리고 timeout에 대처한다.
        # gbn은 duplicate ack에 대해 아무런 조치를 하지 않으니까 그냥 보낸 데이터들 순차적으로 돌면서 ack 확인하면 될 듯
        for pkt_num in range(self.udp_ack_num, self.udp_last_ack_num):
            self.udp_gbn(udp_send_func)
        
        # 파일 전송이 완료되었음을 알리고 ack에 대비한다.
        completion_msg = "File transfer ended".encode(ENCODING)
        self.udp_send_with_record(PACKET_TYPE_FILE_END, completion_msg, udp_send_func)
        self.udp_gbn(udp_send_func)
        # print("S -- 파일 전송 종료")
        
        # 파일 포인터를 제거한다.
        self.file_pointer.close()
        self.file_pointer = None
            
    def udp_file_receive(self, packet: bytes, udp_send_func: Callable) -> int:
        ack_bytes = self.udp_ack_bytes(packet)
        packet_type, ack_num, data = self.udp_packet_unpack(packet)
        # print(f"R -- 뭔가를 받음 {ack_num}")

        if packet_type != PACKET_TYPE_FILE_ACK:
            # 받은 packet에 대한 ack를 전송한다.
            self.udp_ack_send(ack_bytes, udp_send_func)
            # print(f"R -- ack_num {int.from_bytes(ack_bytes, byteorder='big')} 전송")

        if packet_type == PACKET_TYPE_FILE_START:  # file transfer start
            if self.file_pointer is not None:
               self.file_pointer.close()

            basename = data.decode(ENCODING)            
            self.file_name = basename
            file_path = './downloads/(udp) '+basename
            
            # 파일의 이름을 받아 file_path 위치에 self.file_pointer를 생성하고.
            self.file_pointer = open(file_path, 'wb')
            # print("R -- 파일 포인터 생성")
            
            # 그다음 받을 파일의 data의 시작 packet의 ack_num를 self.file_packet_start에 저장하여
            # 연속된 packet을 받을 수 있게 준비한다.
            self.file_packet_start = (ack_num + 1) % UDP_MAX_ACK_NUM
            # print(f"R -- file name 에서 받은 pck_num: {self.file_packet_start}")
            
            return 0

        elif packet_type == PACKET_TYPE_FILE_DATA:  # file transfer
            # print("R -- 파일 데이터 수신")
            if not self.udp_recv_flag[ack_num]:
                # 처음 받은 packet인지 확인하고
                # 처음 받은 packet이라면 self.udp_recv_packet[ack_num]에 저장하고
                # self.udp_recv_flag[ack_num]에서 확인할 수 있게 표시한다.
                self.udp_recv_packet[ack_num] = packet
                self.udp_recv_flag[ack_num] = True
                        
            # self.udp_recv_packet에 self.file_packet_start에서 부터 연속된 --?
            # 패킷이 저장되어 있다면 이를 self.file_pointer를 이용해 파일로 저장하고 
            # self.udp_recv_flag를 update한다.
            # 또한 self.file_packet_start 역시 update한다.
            # print(f"R -- 마지막으로 받은 pkt num: {self.file_packet_start}")
            while self.udp_recv_flag[self.file_packet_start]:
                packet_type, ack_num, data = self.udp_packet_unpack(self.udp_recv_packet[self.file_packet_start])
                self.file_pointer.write(data)
                # print(f"R -- 파일 저장 {self.file_packet_start}")
                self.udp_recv_flag[self.file_packet_start] = False                          # recv_flag에 자리 내주고
                self.file_packet_start = (self.file_packet_start + 1) % UDP_MAX_ACK_NUM     # 마지막으로 수신한 pktnum를 1씩 증가시켜서 연속적으로 받은 pkt만 저장
            return 1

        elif packet_type == PACKET_TYPE_FILE_END:  # file transfer end
            # 파일 전송이 끝난 것을 확인하고 파일을 종료한다.
            if self.file_pointer is not None:
                self.file_pointer.close()
                self.file_pointer = None
            # print("R -- 파일 수신 종료")
            return 2
        
        elif packet_type == PACKET_TYPE_FILE_ACK:  # ack
            # GBN, SR을 위해 self.udp_ack_windows를 update한다.
            self.udp_ack_windows[ack_num] = True
            # print(f"R -- ACK: {ack_num} 수신")
            return 1
        return 1

    def udp_time_out(self) -> bool:
        # 현재시간 - send_base에 저장해 놓은 시간 > threshold
        if time() - self.udp_send_packet[self.udp_ack_num][0] > UDP_TIMEOUT: # timeout
            return True
        else:
            return False

    def udp_gbn(self, udp_send_func: Callable) -> None:
        # GBN, SR 중 하나의 알고리즘을 선택하여 ACK를 관리한다.
        # def udp_gbn () or def udp_sr()로 구현
         # hint: self.udp_send_packet[ack_num]에 저장시
        # (send time, packet)형태로 저장할 것
        # udp_file_send()에서 사용
        # print(f'S -- 윈도우 {len([i for i in self.udp_ack_windows if i == True])} / {len(self.udp_ack_windows)}')
        # send_base에 대한 Ack가 올 때까지 기다리는 코드
        while True:
            # send_base에 대한 Ack가 오면
            # hint: self.udp_ack_num으로 부터 연속되게 ack를 받은 경우 
            # window를 옮겨준다 (self.udp_send_packet에 저장된 packet도 처리해줄 것)
            if self.udp_ack_windows[self.udp_ack_num]:
                self.udp_ack_windows[self.udp_ack_num] = False      # window 자리 비워주고
                self.udp_send_packet.pop(self.udp_ack_num, None)    # 보냈는데 아직 ack 안 온 pkt 목록에서도 뺌
                self.udp_ack_num = (self.udp_ack_num + 1) % UDP_MAX_ACK_NUM # send_base 업데이트
                break
            # Timeout 되면
            elif self.udp_time_out():
                # print('S -- Timeout')
                # send_base ~ nextseqnum-1 까지의 패킷 다시 보냄
                for pkt_num in range(self.udp_ack_num, self.udp_last_ack_num):
                    # print("S -- 재전송 시작")
                    packet = self.udp_send_packet[pkt_num][1]
                    udp_send_func(packet)
                    self.udp_send_packet[pkt_num] = (time(), packet)
                    # print("S -- 재전송 종료")
            else:
                sleep(UDP_WAIT)     # Timeout이 아닌 경우에는 Sleep(UDP_WAIT)를 사용한다.
                    
    def udp_ack_send(self, ack_bytes: bytes, udp_send_func: Callable):
        # 수신한 파일에 대한 ack 전송 : make_pkt + udt_send
        packet = PACKET_TYPE_FILE_ACK + ack_bytes
        packet = self.udp_packet_pack(PACKET_TYPE_FILE_ACK, ack_bytes, b'')
        udp_send_func(packet)
