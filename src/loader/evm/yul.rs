#[derive(Clone, Debug)]
pub struct YulCode {
    // runtime code area
    runtime: String,
}

impl YulCode {
    pub fn new() -> Self {
        YulCode {
            runtime: String::new(),
        }
    }

    pub fn code(&self, base_modulus: String, scalar_modulus: String) -> String {
        format!("
        object \"plonk_verifier\" {{
            code {{
                function allocate(size) -> ptr {{
                    ptr := mload(0x40)
                    if eq(ptr, 0) {{ ptr := 0x60 }}
                    mstore(0x40, add(ptr, size))
                }}
                let size := datasize(\"Runtime\")
                let offset := allocate(size)
                datacopy(offset, dataoffset(\"Runtime\"), size)
                return(offset, size)
            }}

            object \"Runtime\" {{
                code {{
                    function allocate(size) -> ptr {{
                        ptr := mload(0x40)
                        if eq(ptr, 0) {{ ptr := 0x60 }}
                        mstore(0x40, add(ptr, size))
                    }}

                    let success:bool := true
                    let f_p := {base_modulus}
                    let f_q := {scalar_modulus}
                    {}
                }}
            }}
        }}", self.runtime)
    }

    pub fn runtime_append(&mut self, code: String) {
        let mut code = code;
        code.push('\n');
        self.runtime.push_str(&code);
    }
}
