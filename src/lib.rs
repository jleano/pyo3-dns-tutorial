use bytes::{Bytes};
use pyo3::{prelude::*, types::PyBytes};
use byteorder::{BigEndian, ReadBytesExt};  

const CLASS_IN: u16 = 1;

struct Buffer {
    buffer: Bytes,
    curindex: usize // TODO is this correct type?
}
impl Buffer {
    fn get (&mut self) -> Option<&u8>{
        let out = self.buffer.get(self.curindex);
        self.curindex += 1;
        out
    }
    fn slice(&mut self, length: usize) -> Bytes { // TODO convert length to <T>
        let out = self.buffer.slice(self.curindex..self.curindex+length);
        self.curindex += length;
        out
    }
    fn read_u16(&mut self) -> Result<u16, std::io::Error> {
        let out = self.buffer.slice(self.curindex..self.curindex+2).as_ref().read_u16::<BigEndian>();
        self.curindex += 2;
        out
    }
    fn read_u32(&mut self) -> Result<u32, std::io::Error> {
        let out = self.buffer.slice(self.curindex..self.curindex+4).as_ref().read_u32::<BigEndian>();
        self.curindex += 4;
        out
    }
    fn get_length(&mut self) -> u16 {
        let length = match self.get() {
            Some(value) => *value as u16,
            None => {
                panic!("decode name 1; Parsing error: {:?}", self.curindex);
            }
        };
        length
    }
}

#[pyclass]
#[derive(Clone)]
struct DNSQuestion {
    name: Vec<u8>,
    #[pyo3(get, set)]
    type_: u16,
    #[pyo3(get, set)]
    class_: u16
}
#[pymethods]
impl DNSQuestion {
    #[new]
    fn new(name: Vec<u8>, type_: u16, class_: u16) -> DNSQuestion {
        DNSQuestion { name, type_, class_}
    }

    #[getter]
    fn name(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.name).into())
    }
}

#[pyclass]
#[derive(Clone, Debug)]
struct DNSHeader {
    #[pyo3(get, set)]
    id: u16,
    #[pyo3(get, set)]
    flags: u16,
    #[pyo3(get, set)]
    num_question: u16,
    #[pyo3(get, set)]
    num_answers: u16,
    #[pyo3(get, set)]
    num_authorities: u16,
    #[pyo3(get, set)]
    num_additionals: u16
}
#[pymethods]
impl DNSHeader {
    #[new]
    #[pyo3(signature = (id, flags, num_question=0, num_answers=0, num_authorities=0, num_additionals=0))]
    fn new(id: u16, flags: u16, num_question: u16, num_answers: u16, 
        num_authorities: u16, num_additionals: u16) -> DNSHeader {
            DNSHeader { id, flags, num_question, num_answers, num_authorities, num_additionals}
        }
    
}

#[pyclass]
#[derive(Clone)]
struct DNSRecord {
    #[pyo3(set)]
    name: Vec<u8>,
    #[pyo3(get, set)]
    type_: u16,
    #[pyo3(get, set)]
    class_: u16,
    #[pyo3(get, set)]
    ttl:u32,
    #[pyo3(set)]
    data:Vec<u8>
}
#[pymethods]
impl DNSRecord {
    #[new]
    fn new(name: Vec<u8>, type_:u16, class_: u16, ttl: u32, data: Vec<u8>) -> DNSRecord {
        DNSRecord { name, type_, class_, ttl, data}
    }
    #[getter]
    fn name(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.name).into())
    }
    #[getter]
    fn data(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.data).into())
    }

}

#[pyclass]
struct DNSPacket {
    #[pyo3(get, set)]
    header: DNSHeader,
    #[pyo3(get, set)]
    question: Vec<DNSQuestion>,
    #[pyo3(get, set)]
    answers: Vec<DNSRecord>,
    #[pyo3(get, set)]
    authorities: Vec<DNSRecord>,
    #[pyo3(get, set)]
    additionals: Vec<DNSRecord>,
}
#[pymethods]
impl DNSPacket {
    #[new]
    fn new(header: DNSHeader, question: Vec<DNSQuestion>, answers: Vec<DNSRecord>,
        authorities: Vec<DNSRecord>, additionals: Vec<DNSRecord>) -> DNSPacket {
            DNSPacket { header, question, answers, authorities, additionals }
        }

}

#[pyfunction]
fn build_query(py:Python, domain: String, id: u16, reqtype: u16) -> PyObject {
    let name = _encode_dns_name(&domain);
    //let mut rng = thread_rng();  // refactor to method for testing.
    //let id: u16 = rng.gen_range(0..65535);
    let header = DNSHeader{id, num_question:1, flags:0, num_additionals:0, num_answers:0, num_authorities:0};
    let question = DNSQuestion{name, type_: reqtype, class_:CLASS_IN};
    let mut output= vec![];
    output.extend(_header_to_bytes(&header));
    output.extend(_question_to_bytes(&question));
    PyBytes::new(py, &output).into()
}

fn _header_to_bytes(header: &DNSHeader) -> Vec<u8>{
    let mut output = Vec::new();
    // Use to_be_bytes instead of byteorder crate so that you can fit 2byte per int.
    output.extend(header.id.to_be_bytes());
    output.extend(header.flags.to_be_bytes());
    output.extend(header.num_question.to_be_bytes());
    output.extend(header.num_answers.to_be_bytes());
    output.extend(header.num_authorities.to_be_bytes());
    output.extend(header.num_additionals.to_be_bytes());
    output
}
#[pyfunction]
fn header_to_bytes(py: Python, header: &DNSHeader) -> PyObject {
   let output = _header_to_bytes(header);
    PyBytes::new(py, &output).into()
}

fn _question_to_bytes(question: &DNSQuestion) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend(question.name.iter().flat_map(|&byte| byte.to_be_bytes().to_vec()));
    output.extend(question.type_.to_be_bytes());
    output.extend(question.class_.to_be_bytes());
    output
}
#[pyfunction]
fn question_to_bytes(py: Python, question: &DNSQuestion) -> PyObject {
    let output = _question_to_bytes(question);
    PyBytes::new(py, &output).into()
}

fn _encode_dns_name(input: &str) -> Vec<u8>{
    let delimiter: u8 = b'.';
    let mut output = vec![];
    let mut accumulator = vec![];
    for &byte in input.as_bytes() {
        match byte {
            b if b == delimiter => {
                output.push(accumulator.len() as u8);
                output.extend(std::mem::take(&mut accumulator));
                accumulator.clear();
            }
            _ => accumulator.push(byte)
        }
    }
    if !accumulator.is_empty() {
        output.push(accumulator.len() as u8);
        output.extend(std::mem::take(&mut accumulator));
        output.push(0);
    }
    output
}

#[pyfunction]
fn encode_dns_name(py: Python, input: &str) -> PyObject {
    let output = _encode_dns_name(input);
    PyBytes::new(py, &output).into()
}

fn _parse_header(buffer: &mut Buffer) -> DNSHeader {
    let id = buffer.read_u16().unwrap();
    let flags = buffer.read_u16().unwrap();
    let num_question = buffer.read_u16().unwrap();
    let num_answers = buffer.read_u16().unwrap();
    let num_authorities = buffer.read_u16().unwrap();
    let num_additionals = buffer.read_u16().unwrap();
    DNSHeader { id, flags, num_question, num_answers, num_authorities, num_additionals}
}
#[pyfunction]
fn parse_header(_py: Python, input: &[u8]) -> DNSHeader {
    let mut buffer = Buffer {buffer: Bytes::from(input.to_owned()), curindex: 0};
     _parse_header(&mut buffer)
}

fn _decode_name_simple(buffer: &mut Buffer) -> Vec<u8> {
    let mut output = vec![];
    loop {
        let length = match buffer.get() {
            Some(value) => *value as usize,
            None => { println!("Error parsing simple name.");
                    break }
        };
        if length == 0 {
            break
        } else if !output.is_empty() {
            output.push(b'.');
        }
        output.extend(buffer.slice(length).clone());
    }
    output
}
#[pyfunction]
fn decode_name_simple(py: Python, input: &[u8]) -> PyObject {
    let mut buffer = Buffer {buffer: Bytes::from(input.to_owned()), curindex: 0};
    let output = _decode_name_simple(&mut buffer);
    PyBytes::new(py, &output).into()
}

fn _parse_question(buffer: &mut Buffer) -> DNSQuestion {
    let name = _decode_name_simple(buffer);
    let type_ = buffer.read_u16().unwrap();
    let class_ = buffer.read_u16().unwrap();
    DNSQuestion{name, type_, class_}
}
#[pyfunction]
fn parse_question(_py: Python, input: &[u8]) -> DNSQuestion {
    let mut buffer = Buffer{ buffer: Bytes::from(input.to_owned()), curindex: 0};
    _parse_question(&mut buffer)
}

fn _decode_compressed_name(buffer: &mut Buffer, length: u16) -> Vec<u8> {
    let mut output:Vec<u8> = vec![];
    if let Some(value) = buffer.get() {
        let pointer: u16 = ((length & 0b0011_1111) << 8) | (*value as u16);
        let current_index = buffer.curindex;
        buffer.curindex = pointer as usize;
        output.extend(_decode_name(buffer));
        buffer.curindex = current_index;
    }
    output
}
fn _decode_name(buffer: &mut Buffer) -> Vec<u8> {
    let mut parts: Vec<u8> = vec![];
    let mut length = buffer.get_length();

    while length != 0 {
        if (length & 0b1100_0000) == 0b1100_0000 { // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            parts.extend(_decode_compressed_name(buffer, length));
            break
        } else {
            let output = buffer.slice(length as usize);
            parts.extend(output);
            length = buffer.get_length();
            if length != 0 {
                parts.push(b'.')
            }
        }

    }
    parts
}

fn _parse_record(buffer:&mut Buffer) -> DNSRecord {
    let name: Vec<u8> = _decode_name(buffer);
    let type_ = buffer.read_u16().unwrap();
    let class_ = buffer.read_u16().unwrap();
    let ttl = buffer.read_u32().unwrap();
    let data_len = buffer.read_u16().unwrap();
    let data = buffer.slice(data_len as usize);
    let record = DNSRecord {name, type_, class_, ttl, data: data.to_vec()};
    record
}

#[pyfunction]
fn parse_dns_packet(_py: Python, input: &[u8]) -> DNSPacket {
    let mut buffer = Buffer {buffer: Bytes::from(input.to_owned()), curindex: 0};
    let header = _parse_header(&mut buffer);
    let mut question = vec![];
    for _ in 0..header.num_question {
        let ret_question = _parse_question(&mut buffer);
        question.push(ret_question);
    }
    let mut answers = vec![];
    for _ in 0..header.num_answers {
        answers.push(_parse_record(&mut buffer));
    }
    let mut authorities = vec![];
    for _ in 0..header.num_authorities{
        authorities.push(_parse_record(&mut buffer));
    }
    let mut additionals = vec![];
    for _ in 0..header.num_additionals{
        additionals.push(_parse_record(&mut buffer));
    }
    DNSPacket { header, question, answers, authorities, additionals }
}

/// Formats the sum of two numbers as string.
#[pyfunction] fn sum_as_string(a: usize, b: usize) -> PyResult<String> { Ok((a + b).to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn dns(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(parse_header, m)?)?;
    m.add_function(wrap_pyfunction!(encode_dns_name, m)?)?;
    m.add_function(wrap_pyfunction!(header_to_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(question_to_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(build_query, m)?)?;
    m.add_function(wrap_pyfunction!(decode_name_simple, m)?)?;
    m.add_function(wrap_pyfunction!(parse_question, m)?)?;
    m.add_function(wrap_pyfunction!(parse_dns_packet, m)?)?;
    m.add_class::<DNSHeader>()?;
    m.add_class::<DNSQuestion>()?;
    m.add_class::<DNSRecord>()?;
    m.add_class::<DNSPacket>()?;
    Ok(())
}