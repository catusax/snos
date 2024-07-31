use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::BuiltinRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::Felt252;
use starknet_os::error::SnOsError;

pub fn get_output(vm: &VirtualMachine) -> Result<Vec<Felt252>, SnOsError> {
    let (output_base, output_size) = get_output_info(vm)?;
    let raw_output = get_raw_output(vm, output_base, output_size)?;
    Ok(raw_output)
}

/// Gets the output base segment and the output size from the VM return values and the VM
/// output builtin.
fn get_output_info(vm: &VirtualMachine) -> Result<(usize, usize), SnOsError> {
    let n_builtins = vm.get_builtin_runners().len();
    let builtin_end_ptrs = vm.get_return_values(n_builtins).map_err(|e| SnOsError::CatchAll(e.to_string()))?;
    let output_base = vm
        .get_builtin_runners()
        .iter()
        .find(|&elt| matches!(elt, BuiltinRunner::Output(_)))
        .expect("Os vm should have the output builtin")
        .base();

    let output_size = match builtin_end_ptrs[0] {
        MaybeRelocatable::Int(_) => {
            return Err(SnOsError::CatchAll("expected a relocatable as output builtin end pointer".to_string()));
        }
        MaybeRelocatable::RelocatableValue(address) => {
            if address.segment_index as usize != output_base {
                return Err(SnOsError::CatchAll(format!(
                    "output builtin end pointer ({address}) is not on the expected segment ({output_base})"
                )));
            }
            address.offset
        }
    };

    Ok((output_base, output_size))
}

/// Gets the OS output as an array of felts based on the output base and size.
fn get_raw_output(vm: &VirtualMachine, output_base: usize, output_size: usize) -> Result<Vec<Felt252>, SnOsError> {
    // Get output and check that everything is an integer.
    let raw_output = vm.get_range((output_base as isize, 0).into(), output_size);
    let raw_output: Result<Vec<Felt252>, _> = raw_output
        .iter()
        .map(|x| {
            if let MaybeRelocatable::Int(val) = x.clone().unwrap().into_owned() {
                Ok(val)
            } else {
                Err(SnOsError::CatchAll("Output should be all integers".to_string()))
            }
        })
        .collect();

    raw_output
}
