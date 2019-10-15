// extern crate enigma_core_app;

// #[macro_use]
// extern crate log;
// extern crate log_derive;

// pub use enigma_core_app::*;
// pub use esgx::ocalls_u::{ocall_get_deltas, ocall_get_deltas_sizes, ocall_get_state, ocall_get_state_size,
//                                 ocall_new_delta, ocall_update_state};
// pub use enigma_tools_u::esgx::ocalls_u::{ocall_get_home, ocall_save_to_memory};
// use enigma_tools_u::common_u::logging;
// use networking::{ipc_listener, IpcListener};
// use db::DB;
// use cli::Opt;
// use structopt::StructOpt;
// use futures::Future;
// use simplelog::CombinedLogger;

// fn main() {
//     let opt: Opt = Opt::from_args();
//     debug!("CLI params: {:?}", opt);

//     let datadir = opt.data_dir.clone().unwrap_or_else(|| dirs::home_dir().unwrap().join(".enigma"));
//     let loggers = logging::get_logger(opt.debug_stdout, datadir.clone(), opt.verbose).expect("Failed Creating the loggers");
//     CombinedLogger::init(loggers).expect("Failed initializing the logger");

//     let enclave = esgx::general::init_enclave_wrapper().expect("[-] Init Enclave Failed");
//     let eid = enclave.geteid();
//     info!("[+] Init Enclave Successful {}!", eid);
//     println!("[+] Init Enclave Successful {}!", eid);
//     let mut db = DB::new(datadir, true).expect("Failed initializing the DB");
//     let server = IpcListener::new(&format!("tcp://*:{}", opt.port));

//     server
//         .run(move |multi| ipc_listener::handle_message(&mut db, multi, &opt.spid, eid))
//         .wait()
//         .unwrap();
// }
#![allow(dead_code, unused_assignments, unused_variables)]
extern crate enigma_core_app;
extern crate sgx_urts;
extern crate sgx_types;
extern crate serde;
extern crate enigma_types;
use serde::{Serialize,Deserialize};
pub use enigma_core_app::*;
use esgx;
use sgx_types::*;
use evm_u::evm;
use enigma_core_app::evm_u::evm::EvmRequest;
// use enigma_types::traits::SliceCPtr;
use sgx_urts::SgxEnclave;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};



fn read_input_from_file(path: &str) -> evm::EvmInput {
    let file = match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", path, why),
        Ok(file) => file,
    };

    let mut lines = BufReader::new(file).lines();
    evm::EvmInput { data: lines.next().unwrap().unwrap(), code: lines.next().unwrap().unwrap() }
}

fn init_enclave() -> SgxEnclave {
    match esgx::general::init_enclave_wrapper() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            panic!("[-] Init Enclave Failed {}!", x.as_str());
        }
    }
}

pub fn main() {
    let evm_input = EvmRequest {
        bytecode: "608060405260043610610057576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063748c8b561461005c5780639867db74146101f4578063bb4c4f1c1461025d575b600080fd5b34801561006857600080fd5b50610179600480360381019080803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919291929080359060200190929190803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919291929080359060200190929190803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290803590602001909291908035151590602001909291905050506102ed565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156101b957808201518184015260208101905061019e565b50505050905090810190601f1680156101e65780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561020057600080fd5b5061025b600480360381019080803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290505050610354565b005b34801561026957600080fd5b5061027261036e565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156102b2578082015181840152602081019050610297565b50505050905090810190601f1680156102df5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6060808890508215156103125760206040519081016040528060008152509150610348565b8786101580156103225750838610155b1561032b578690505b85841015801561033b5750878410155b15610344578490505b8091505b50979650505050505050565b806000908051906020019061036a929190610410565b5050565b606060008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156104065780601f106103db57610100808354040283529160200191610406565b820191906000526020600020905b8154815290600101906020018083116103e957829003601f168201915b5050505050905090565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061045157805160ff191683800117855561047f565b8280016001018555821561047f579182015b8281111561047e578251825591602001919060010190610463565b5b50905061048c9190610490565b5090565b6104b291905b808211156104ae576000816000905550600101610496565b5090565b905600a165627a7a723058206f0d5f44e0e2b23b717de1c46d45ee75b7660bf9d82e379aeb63ad7a8de85a8c0029".to_string(),

        callable: "check(string,uint,string,uint,string,uint,bool)".to_string(),
        // RLP-encoded: [1,"aaa",2,"bbb",3,"ccc", True]
        callable_args: "d083616161018362626202836363630301".to_string(),
        preprocessor: [].to_vec(),
        callback : "commit(string)".to_string(),
    };
    let enclave = init_enclave();
    let evm_result = match evm::exec_evm(enclave.geteid(), evm_input) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", e.to_string());
            return;
        }
    };
    enclave.destroy();
    println!("{:?}",evm_result);
}