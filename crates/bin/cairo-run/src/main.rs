use std::fs;

use blockifier::context::BlockContext;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::Felt252;
use clap::Parser;
use run_os::StarknetOsInput;
use serde::Deserialize;
use serde_json::Number;
use starknet_os::execution::helper::{ContractStorageMap, ExecutionHelperWrapper};
use starknet_os::storage::dict_storage::DictStorage;

mod hint_processor;
mod output;
mod run_os;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    contract_class: String,
    #[arg(long)]
    program_input: String,
    #[arg(long)]
    os: String,
}

fn main() {
    let args = Args::parse();

    let compiled_contract = fs::read(args.contract_class).expect("can not read contract_class");
    let os_input: StarknetOsInput = serde_json::from_slice(&compiled_contract).expect("can not parse contract_class");

    let program_input_json = fs::read(args.program_input).expect("can not read program_input");

    let compiled_os = fs::read(args.os).expect("can not read os");

    let contract_input: ContractInput =
        serde_json::from_slice(&program_input_json).expect("can not parse program_input");

    let block_context = BlockContext::create_for_testing();

    let execution_helper: ExecutionHelperWrapper<DictStorage> = ExecutionHelperWrapper::new(
        ContractStorageMap::new(),
        vec![],
        &block_context,
        (Felt252::from(0), Felt252::from(0)),
    );

    println!("Running OS...");
    println!("{:#?}", contract_input.to_felt());

    run_os::run_os(&compiled_os, LayoutName::starknet_with_keccak, os_input, contract_input.to_felt(), execution_helper).unwrap();
}

#[derive(Debug, Deserialize)]
struct ContractInput {
    pub inputs: Vec<Number>,
}

impl ContractInput {
    fn to_felt(&self) -> Vec<Felt252> {
        self.inputs.iter().map(|x| Felt252::from_dec_str(&x.as_str()).unwrap()).collect()
    }
}
