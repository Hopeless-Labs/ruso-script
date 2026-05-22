use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "script/grammar.pest"]
pub struct ScannerParser;
