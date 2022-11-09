use crate::{
    loader::{
        evm::{
            MemoryChunk,
            yulloader::*,
            EvmYulLoader,
        },
        Loader,
    },
    util::{
        arithmetic::{
            CurveAffine,
            PrimeField,
        },
        Itertools,
        transcript::{
            Transcript,
            TranscriptRead,
        }
    },
    Error
};
use std::{
    iter,
    marker::PhantomData,
    rc::Rc,
};

pub struct EvmYulTranscript<C: CurveAffine, L: Loader<C>, S, B> {
    loader: L,
    stream: S,
    buf: B,
    _marker: PhantomData<C>,
}

impl<C> EvmYulTranscript<C, Rc<EvmYulLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    pub fn new(loader: Rc<EvmYulLoader>) -> Self {
        let ptr = loader.allocate(0x20);
        assert_eq!(ptr, 0x80);
        let mut buf = MemoryChunk::new(ptr);
        buf.extend(0x20);
        Self {
            loader,
            stream: 0,
            buf,
            _marker: PhantomData,
        }
    }

    pub fn load_instances(&mut self, num_instance: Vec<usize>) -> Vec<Vec<Scalar>> {
        num_instance
            .into_iter()
            .map(|len| {
                iter::repeat_with(|| {
                    let scalar = self.loader.calldataload_scalar(self.stream);
                    self.stream += 0x20;
                    scalar
                })
                .take(len)
                .collect_vec()
            })
            .collect()
    }
}

impl<C> Transcript<C, Rc<EvmYulLoader>> for EvmYulTranscript<C, Rc<EvmYulLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &Rc<EvmYulLoader> {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> Scalar {
        let len = if self.buf.len() == 0x20 {
            assert_eq!(self.loader.ptr(), self.buf.end());
            let buf_end = self.buf.end();
            let code = format!("mstore8({buf_end}, 1)");
            self.loader
                .code_mut()
                .runtime_append(code);
            0x21
        } else {
            self.buf.len()
        };
        let hash_ptr = self.loader.keccak256(self.buf.ptr(), len);

        let challenge_ptr = self.loader.allocate(0x20);
        let dup_hash_ptr = self.loader.allocate(0x20);
        let code = format!("{{
            let hash := mload({hash_ptr})
            mstore({challenge_ptr}, mod(hash, f_q))
            mstore({dup_hash_ptr}, hash)
        }}");
        self.loader
            .code_mut()
            .runtime_append(code);
        
        self.buf.reset(dup_hash_ptr);
        self.buf.extend(0x20);

        self.loader.scalar(Value::Memory(challenge_ptr))
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint) -> Result<(), Error> {
        if let Value::Memory(ptr) = ec_point.value() {
            assert_eq!(self.buf.end(), ptr);
            self.buf.extend(0x40);
        } else {
            unreachable!()
        }
        Ok(())
    }

    fn common_scalar(&mut self, scalar: &Scalar) -> Result<(), Error> {
        match scalar.value() {
            Value::Constant(_) if self.buf.ptr() == 0x80 => {
                self.loader.copy_scalar(scalar, self.buf.ptr());
            }
            Value::Memory(ptr) => {
                assert_eq!(self.buf.end(), ptr);
                self.buf.extend(0x20);
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl<C> TranscriptRead<C, Rc<EvmYulLoader>> for EvmYulTranscript<C, Rc<EvmYulLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn read_scalar(&mut self) -> Result<Scalar, Error> {
        let scalar = self.loader.calldataload_scalar(self.stream);
        self.stream += 0x20;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint, Error> {
        let ec_point = self.loader.calldataload_ec_point(self.stream);
        self.stream += 0x40;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}
