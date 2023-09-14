#!/usr/bin/env python

import dns
import random
import unittest
from io import BytesIO
import pydns
import part_2
from part_2 import decode_name_simple, parse_header, parse_question, parse_dns_packet, DNSRecord
from part_1 import (
    encode_dns_name,
    DNSHeader,
    header_to_bytes,
    question_to_bytes,
    DNSQuestion,
    TYPE_A,
    CLASS_IN,
)


class TestDns(unittest.TestCase):
    # POC that this works
    def test_sum_as_string(self):
        self.assertEqual(dns.sum_as_string(4, 5), "9")

    # build_query(domain_name, record_type)
    def test_build_query(self):
        id = random.randint(0, 65535)
        calibration = b"D\xcb\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        args = ("google.com", id, 1)
        ret = pydns.build_query(*args)
        self.assertEqual(calibration, ret)

        rret = dns.build_query(*args)
        self.assertEqual(calibration, rret)

    def test_encode_dns_name(self):
        calibration = b"\x06google\x03com\x00"

        pyencoded = encode_dns_name("google.com")
        self.assertEqual(pyencoded, calibration)

        rencoded = dns.encode_dns_name("google.com")
        self.assertEqual(rencoded, calibration)

    def test_header_to_bytes(self):
        calibration = b"\x13\x88\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        header = DNSHeader(id=5000, num_question=1, flags=0)
        pybytes = header_to_bytes(header)
        self.assertEqual(pybytes, calibration)

        rheader = dns.DNSHeader(id=5000, flags=0, num_question=1)
        rbytes = dns.header_to_bytes(rheader)
        self.assertEqual(rbytes, calibration)

    def test_header_to_bytes_max(self):
        calibration = b"\x80\xe8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        # Handle id large enough to confirm unsigned int is being used.
        header = DNSHeader(id=33000, num_question=1, flags=0)
        pybytes = header_to_bytes(header)
        self.assertEqual(pybytes, calibration)

        rheader = dns.DNSHeader(id=33000, flags=0, num_question=1)
        rbytes = dns.header_to_bytes(rheader)
        self.assertEqual(rbytes, calibration)

    def test_question_to_bytes(self):
        calibration = b"\x06google\x03com\x00\x00\x01\x00\x01"
        name = encode_dns_name("google.com")
        question = DNSQuestion(name, TYPE_A, CLASS_IN)
        pyencoded = question_to_bytes(question)
        self.assertEqual(calibration, pyencoded)

        rquestion = dns.DNSQuestion(name, TYPE_A, CLASS_IN)
        rencoded = dns.question_to_bytes(rquestion)
        self.assertEqual(calibration, rencoded)

    def test_parse_header(self):
        header = b"u \x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
        pyheader = parse_header(BytesIO(header))
        rheader = dns.parse_header(header)
        for attr in ('id', 'flags', 'num_question', 'num_answers', 'num_authorities', 'num_additionals'):
            #print('checking for attr: ', attr)
            #print(getattr(pyheader, attr), getattr(rheader, attr))
            self.assertEqual(getattr(pyheader, attr), getattr(rheader, attr))
    
    def test_parse_name_simple(self):
        calibration = b'\x07example\x03com\x00'
        output = b'example.com'
        pyname = decode_name_simple(BytesIO(calibration))
        self.assertEqual(pyname, output)

        rname = dns.decode_name_simple(calibration)
        self.assertEqual(rname, output)
        
    def test_parse_question(self):
        input = b'\x08facebook\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01,\x00\x04\x9d\xf0\x18#'
        data = BytesIO(input)
        pyquestion = parse_question(data)
        self.assertEqual(pyquestion.name, b'facebook.com')
        self.assertEqual(pyquestion.type_, 1)
        self.assertEqual(pyquestion.class_, 1)

        rquestion = dns.parse_question(input)
        self.assertEqual(rquestion.name, b'facebook.com')
        self.assertEqual(rquestion.type_, 1)
        self.assertEqual(rquestion.class_, 1)
        
    #@unittest.skip
    def test_parse_dns_packet(self):
        # 1 1 0 0
        input = (b'\x88\\\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01a\x0ciana-servers'
            b'\x03net\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x07\x08\x00\x04\xc7+\x875')

        pypacket = parse_dns_packet(input)
        #print(pypacket.header)
        #print(pypacket.question)
        #print(type(pypacket.question[0]))
        #print(pypacket.answers)
        #print(pypacket.answers)
        #print(pypacket.authorities)
        #print(pypacket.additionals)
        self.assertTrue(pypacket.header)
        self.assertIsInstance(pypacket.header, DNSHeader)
        self.assertEqual(len(pypacket.question), 1)
        self.assertIsInstance(pypacket.question[0], DNSQuestion)
        self.assertEqual(len(pypacket.answers), 1)
        self.assertIsInstance(pypacket.answers[0], part_2.DNSRecord)
        self.assertEqual(pypacket.answers[0].name, b'a.iana-servers.net')
        self.assertFalse(pypacket.authorities)
        self.assertFalse(pypacket.additionals)

        rpacket = dns.parse_dns_packet(input)

        #print(rpacket.header)
        #print(rpacket.question)
        #print(type(rpacket.question[0]))
        #print(rpacket.answers)
        #print(rpacket.answers)
        #print(rpacket.authorities)
        #print(rpacket.additionals)
        self.assertTrue(rpacket.header)
        self.assertIsInstance(rpacket.header, dns.DNSHeader)
        self.assertEqual(len(rpacket.question), 1)
        self.assertIsInstance(rpacket.question[0], dns.DNSQuestion)
        self.assertEqual(len(rpacket.answers), 1)
        self.assertIsInstance(rpacket.answers[0], dns.DNSRecord)
        self.assertEqual(rpacket.answers[0].name, b'a.iana-servers.net')
        self.assertFalse(rpacket.authorities)
        self.assertFalse(rpacket.additionals)

    def test_parse_name(self):
        input = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x07\x08\x00\x04\xc7+\x875'


if __name__ == "__main__":
    unittest.main()
    #TestDns().test_parse_dns_packet()
    #TestDns().test_parse_question()
    #TestDns().test_parse_name_simple()
