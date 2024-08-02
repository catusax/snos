use std::collections::HashMap;

use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
use cairo_vm::hint_processor::hint_processor_definition::{
    HintExtension, HintProcessor, HintProcessorLogic, HintReference,
};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;
use starknet_os::cairo_types::structs::{CompiledClass, CompiledClassFact};
use starknet_os::execution::syscall_handler::OsSyscallHandlerWrapper;
use starknet_os::hints::{vars, SnosHintProcessor};
use starknet_os::io::classes::write_class;
use starknet_os::storage::storage::Storage;

use crate::run_os::StarknetOsInput;

pub fn new_hint_processor<S>() -> SnosHintProcessor<S>
where
    S: Storage + 'static,
{
    let mut processor = SnosHintProcessor::default();

    processor.hints.insert(LOAD_CLASS_FACTS.into(), load_compiled_class);
    processor.hints.insert(OS_LOAD_CONTRACT_DATA.into(), load_class_inner);
    processor.hints.insert(BYTECODE_NO_FOOTER_SET.into(), do_nothing);
    processor.hints.insert(BYTECODE_FOOTER_SET.into(), do_nothing);
    processor.hints.insert(LOAD_CONTRACT_ARG.into(), load_contract_arg);

    processor.hints.insert(SETUP_SYSCALL.into(), set_syscall_ptr::<S>);
    processor.hints.insert(PRINT1.into(), print1);
    processor.hints.insert(PRINT2.into(), do_nothing);

    processor.extensive_hints.insert(LOAD_CLASS.into(), load_class);

    processor
}

pub const LOAD_CLASS_FACTS: &str = indoc! {r#"
    from core.objects import ContractBootloaderInput
    compiled_class = ContractBootloaderInput.Schema().load(program_input).compiled_class"#
};

pub fn load_compiled_class(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;

    let class = os_input.compiled_class;

    exec_scopes.insert_value(vars::scopes::COMPILED_CLASS, class.clone()); //TODO: is this clone necessary?

    Ok(())
}

pub fn do_nothing(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    Ok(())
}

pub const OS_LOAD_CONTRACT_DATA: &str = indoc! {r#"
    from starkware.starknet.core.os.contract_class.compiled_class_hash import create_bytecode_segment_structure
    from contract_class.compiled_class_hash_utils import get_compiled_class_struct

    bytecode_segment_structure_no_footer = create_bytecode_segment_structure(
        bytecode=compiled_class.bytecode,
        bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
        visited_pcs=None,
    )

    bytecode_segment_structure_with_footer = create_bytecode_segment_structure(
        bytecode=compiled_class.bytecode,
        bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
        visited_pcs=None,
    )

    bytecode_segment_structure = bytecode_segment_structure_with_footer

    cairo_contract = get_compiled_class_struct(
        compiled_class=compiled_class,
        bytecode=bytecode_segment_structure.bytecode_with_skipped_segments()
    )
    ids.compiled_class = segments.gen_arg(cairo_contract)"#
};

pub fn load_class_inner(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let os_input = exec_scopes.get::<StarknetOsInput>(vars::scopes::OS_INPUT)?;

    let class = os_input.compiled_class;

    exec_scopes.insert_value(vars::scopes::COMPILED_CLASS, class.clone()); //TODO: is this clone necessary?

    // TODO: implement create_bytecode_segment_structure (for partial code loading)

    let class_base = vm.add_memory_segment();
    write_class(vm, class_base, class.clone())?; //TODO: clone unnecessary

    insert_value_from_var_name(vars::ids::COMPILED_CLASS, class_base, vm, ids_data, ap_tracking)
}

pub const BYTECODE_NO_FOOTER_SET: &str = indoc! {r#"
    bytecode_segment_structure = bytecode_segment_structure_no_footer"#
};

pub const BYTECODE_FOOTER_SET: &str = indoc! {r#"
    bytecode_segment_structure = bytecode_segment_structure_with_footer"#
};

pub const LOAD_CLASS: &str = indoc! {r#"
    vm_load_program(
        compiled_class.get_runnable_program(entrypoint_builtins=[]),
        ids.compiled_class.bytecode_ptr
    )"#
};

pub fn load_class(
    _hint_processor: &dyn HintProcessor,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<HintExtension, HintError> {
    let class = exec_scopes.get::<CasmContractClass>(vars::scopes::COMPILED_CLASS)?;

    let compiled_class_ptr = get_ptr_from_var_name(vars::ids::COMPILED_CLASS, vm, ids_data, ap_tracking)?;
    let byte_code_ptr = vm.get_relocatable((compiled_class_ptr + CompiledClass::bytecode_ptr_offset())?)?;

    let mut hint_extension = HintExtension::new();

    for (rel_pc, hints) in class.hints.into_iter() {
        let abs_pc = Relocatable::from((byte_code_ptr.segment_index, rel_pc));
        hint_extension.insert(abs_pc, hints.iter().map(|h| any_box!(h.clone())).collect());
    }

    Ok(hint_extension)
}

pub const LOAD_CONTRACT_ARG: &str = indoc! {r#"
    from core.utils import get_contract_inputs
    ids.calldata = segments.add()
    inputs =  get_contract_inputs()
    ids.calldata_size = len(inputs)
    print(len(inputs))
    segments.write_arg(ids.calldata, inputs)"#
};

pub fn load_contract_arg(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    // this hint fills in a Cairo BigInt3 by taking a felt (ids.value) and passing it to a split fn
    let value = exec_scopes.get::<Vec<Felt252>>("contract_input")?;

    let value: Vec<MaybeRelocatable> = value.into_iter().map(|v| MaybeRelocatable::from(v)).collect();

    let new_segment_calldata = vm.add_memory_segment();
    insert_value_from_var_name(vars::ids::CALLDATA, new_segment_calldata, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name("calldata_size", value.len(), vm, ids_data, ap_tracking)?;

    vm.write_arg(new_segment_calldata, &value)?;

    Ok(())
}

pub const SETUP_SYSCALL: &str = indoc! {r#"
    print("contract_entry_point:" , ids.contract_entry_point)
    ids.syscall_ptr = segments.add()
    from core.runtime.syscall_handler import SyscallHandler
    syscall_handler = SyscallHandler(segments=segments)
    syscall_handler.set_syscall_ptr(syscall_ptr=ids.syscall_ptr)"#
};

pub fn set_syscall_ptr<S>(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError>
where
    S: Storage + 'static,
{
    let syscall_ptr = vm.add_memory_segment();

    insert_value_from_var_name(vars::ids::SYSCALL_PTR, syscall_ptr, vm, ids_data, ap_tracking)?;

    let syscall_handler: OsSyscallHandlerWrapper<S> = exec_scopes.get(vars::scopes::SYSCALL_HANDLER)?;
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(syscall_handler.set_syscall_ptr(syscall_ptr));

    Ok(())
}

pub const PRINT1: &str = indoc! {r#"
    print("builtin_ptrs:" , ids.builtin_ptrs)
    print("syscall_ptr:" , ids.syscall_ptr)
    print("calldata_start:" , ids.calldata_start)
    print("calldata_end:" , ids.calldata_end)"#
};

pub fn print1(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let syscall_ptr = get_ptr_from_var_name(vars::ids::CALLDATA, vm, ids_data, ap_tracking)?;
    let syscall_len = get_integer_from_var_name("calldata_size", vm, ids_data, ap_tracking)?;

    let syscall_len_str = syscall_len.to_bytes_be();

    let len = u32::from_be_bytes([syscall_len_str[0], syscall_len_str[1], syscall_len_str[2],
    syscall_len_str[3]]);

    for i in 0..len {
        let syscall_value = vm.get_integer((syscall_ptr + i)?)?;
        println!("syscall_value: {:#?}", syscall_value);
    }

    Ok(())
}

pub const PRINT2: &str = indoc! {r#"
    print(ids.entry_point_return_values.failure_flag)
    for i in range(0, ids.retdata_size):
        print(memory[ids.retdata_start + i])"#
};
