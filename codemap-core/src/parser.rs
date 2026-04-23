use crate::types::*;

pub struct ParseResult {
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub functions: Vec<FunctionInfo>,
    pub data_flow: Option<FileDataFlow>,
    pub urls: Vec<String>,
}

pub fn parse_file(_path: &str, _content: &str, _ext: &str) -> ParseResult {
    ParseResult { imports: vec![], exports: vec![], functions: vec![], data_flow: None, urls: vec![] }
}
