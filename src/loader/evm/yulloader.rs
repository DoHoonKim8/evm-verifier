use crate::{
    util::{
        arithmetic::{CurveAffine, PrimeField, FieldOps}
    },
    loader::{
        EcPointLoader,
        Loader,
        evm::{
            code::Precompiled,
            yul::YulCode,
            fe_to_u256,
            modulus,
        },
        LoadedEcPoint, ScalarLoader, LoadedScalar,
    },
    Error,
};
use ethereum_types::{U256, U512,};
use std::{
    cell::RefCell,
    rc::Rc,
    fmt::{self, Debug},
    collections::HashMap,
    ops::{MulAssign, SubAssign, AddAssign, Add, Mul, Neg, Sub, DerefMut}
};
extern crate hex;

#[derive(Clone, Debug)]
pub enum Value<T> {
    Constant(T),
    Memory(usize),
    Negated(Box<Value<T>>),
    Sum(Box<Value<T>>, Box<Value<T>>),
    Product(Box<Value<T>>, Box<Value<T>>),
}

impl<T: Debug> PartialEq for Value<T> {
    fn eq(&self, other: &Self) -> bool {
        self.identifier() == other.identifier()
    }
}

impl<T: Debug> Value<T> {
    fn identifier(&self) -> String {
        match &self {
            Value::Constant(_) | Value::Memory(_) => format!("{:?}", self),
            Value::Negated(value) => format!("-({:?})", value),
            Value::Sum(lhs, rhs) => format!("({:?} + {:?})", lhs, rhs),
            Value::Product(lhs, rhs) => format!("({:?} * {:?})", lhs, rhs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EvmYulLoader {
    base_modulus: U256,
    scalar_modulus: U256,
    code: RefCell<YulCode>,
    // EVM memory offset
    ptr: RefCell<usize>,
    // memory allocation count
    mem_count: usize,
    cache: RefCell<HashMap<String, usize>>,
    #[cfg(test)]
    gas_metering_ids: RefCell<Vec<String>>,
}

#[derive(Clone)]
pub struct Scalar {
    loader: Rc<EvmYulLoader>,
    value: Value<U256>,
}

fn hex_encode_u256(value: &U256) -> String {
    let mut bytes = [0; 32];
    value.to_big_endian(&mut bytes);
    format!("0x{}", hex::encode(bytes))
}

impl Scalar {
    pub(crate) fn loader(&self) -> &Rc<EvmYulLoader> {
        &self.loader
    }

    pub(crate) fn value(&self) -> Value<U256> {
        self.value.clone()
    }

    pub(crate) fn is_const(&self) -> bool {
        matches!(self.value, Value::Constant(_))
    }

    pub(crate) fn ptr(&self) -> usize {
        match self.value {
            Value::Memory(ptr) => ptr,
            _ => *self
                .loader
                .cache
                .borrow()
                .get(&self.value.identifier())
                .unwrap(),
        }
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &self.value)
            .finish()
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.loader.add(&self, &rhs)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.loader.sub(&self, &rhs)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        self.loader.mul(&self, &rhs)
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        self.loader.neg(&self)
    }
}

impl<'a> Add<&'a Self> for Scalar {
    type Output = Self;

    fn add(self, rhs: &'a Self) -> Self {
        self.loader.add(&self, rhs)
    }
}

impl<'a> Sub<&'a Self> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &'a Self) -> Self {
        self.loader.sub(&self, rhs)
    }
}

impl<'a> Mul<&'a Self> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &'a Self) -> Self {
        self.loader.mul(&self, rhs)
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.loader.add(self, &rhs);
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.loader.sub(self, &rhs);
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.loader.mul(self, &rhs);
    }
}

impl<'a> AddAssign<&'a Self> for Scalar {
    fn add_assign(&mut self, rhs: &'a Self) {
        *self = self.loader.add(self, rhs);
    }
}

impl<'a> SubAssign<&'a Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'a Self) {
        *self = self.loader.sub(self, rhs);
    }
}

impl<'a> MulAssign<&'a Self> for Scalar {
    fn mul_assign(&mut self, rhs: &'a Self) {
        *self = self.loader.mul(self, rhs);
    }
}

impl FieldOps for Scalar {
    fn invert(&self) -> Option<Scalar> {
        Some(self.loader.invert(self))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<F: PrimeField<Repr = [u8; 0x20]>> LoadedScalar<F> for Scalar {
    type Loader = Rc<EvmYulLoader>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }


}

impl EvmYulLoader {
    pub fn new<Base, Scalar>() -> Rc<Self>
    where
        Base: PrimeField<Repr = [u8; 0x20]>,
        Scalar: PrimeField<Repr = [u8; 32]>,
    {
        let base_modulus = modulus::<Base>();
        let scalar_modulus = modulus::<Scalar>();

        let code = YulCode::new();

        Rc::new(Self {
            base_modulus,
            scalar_modulus,
            code: RefCell::new(code),
            ptr: RefCell::new(0x80),
            mem_count: 0,
            cache: Default::default(),
            #[cfg(test)]
            gas_metering_ids: RefCell::new(Vec::new()),
        })
    }

    pub fn runtime_code(self: &Rc<Self>) -> String {
        let code = format!("if not(success) {{ revert(0, 0) }}
            return(0, 0)");
        self.code.borrow_mut().runtime_append(code);
        self.code.borrow().code(
            hex_encode_u256(&self.base_modulus),
            hex_encode_u256(&self.scalar_modulus)
        )
    }

    pub fn allocate(self: &Rc<Self>, size: usize) -> usize {
        let ptr = *self.ptr.borrow();
        *self.ptr.borrow_mut() += size;
        ptr
    }

    pub(crate) fn scalar_modulus(&self) -> U256 {
        self.scalar_modulus
    }

    pub(crate) fn ptr(&self) -> usize {
        *self.ptr.borrow()
    }

    pub(crate) fn code_mut(&self) -> impl DerefMut<Target = YulCode> + '_ {
        self.code.borrow_mut()
    }

    fn push(self: &Rc<Self>, scalar: &Scalar) -> String {
        match scalar.value.clone() {
            Value::Constant(constant) => {
                format!("{constant}")
            }
            Value::Memory(ptr) => {
                format!("mload({ptr:#x})")
            }
            Value::Negated(value) => {
                let v = self.push(&self.scalar(*value));
                format!("sub(f_q, {v})")
            }
            Value::Sum(lhs, rhs) => {
                let lhs = self.push(&self.scalar(*lhs));
                let rhs = self.push(&self.scalar(*rhs));
                format!("addmod({lhs}, {rhs}, f_q)")
            }
            Value::Product(lhs, rhs) => {
                let lhs = self.push(&self.scalar(*lhs));
                let rhs = self.push(&self.scalar(*rhs));
                format!("mulmod({lhs}, {rhs}, f_q)")
            }
        }
    }

    pub fn calldataload_scalar(self: &Rc<Self>, offset: usize) -> Scalar {
        let ptr = self.allocate(0x20);
        let code = format!("mstore({ptr:#x}, mod(calldataload({offset:#x}), f_q))");
        self.code.borrow_mut().runtime_append(code);
        self.scalar(Value::Memory(ptr))
    }

    pub fn calldataload_ec_point(self: &Rc<Self>, offset: usize) -> EcPoint {
        let x_ptr = self.allocate(0x40);
        let y_ptr = x_ptr + 0x20;
        let x_offset = offset;
        let y_offset = offset + 0x20;
        let validate_code = self.validate_ec_point();
        let code = format!("
        {{
            let x := calldataload({x_offset:#x})
            mstore({x_ptr:#x}, x)
            let y := calldataload({y_offset:#x})
            mstore({y_ptr:#x}, y)
            {validate_code}
        }}");
        self.code.borrow_mut().runtime_append(code);
        self.ec_point(Value::Memory(x_ptr))
    }

    fn validate_ec_point(self: &Rc<Self>) -> String {
        let code = format!("{{
            let valid:bool
            {{
                let x_lt_p:bool := lt(x, f_p)
                let y_lt_p:bool := lt(y, f_p)
                valid := and(x_lt_p, y_lt_p)
            }}
            {{
                let x_is_zero:bool := eq(x, 0)
                let y_is_zero:bool := eq(y, 0)
                let x_or_y_is_zero:bool := or(x_is_zero, y_is_zero)
                let x_and_y_is_not_zero:bool := not(x_or_y_is_zero)
                valid := and(x_and_y_is_not_zero, valid)
            }}
            {{
                let y_square := mulmod(y, y, f_p)
                let x_square := mulmod(x, x, f_p)
                let x_cube := mulmod(x_square, x, f_p)
                let x_cube_plus_3 := addmod(x_cube, 3, f_p)
                let y_square_eq_x_cube_plus_3:bool := eq(x_cube_plus_3, y_square)
                valid := and(y_square_eq_x_cube_plus_3, valid)
            }}
            success := and(valid, success)
        }}");
        code
    }

    pub(crate) fn scalar(self: &Rc<Self>, value: Value<U256>) -> Scalar {
        let value = if matches!(
            value,
            Value::Constant(_) | Value::Memory(_) | Value::Negated(_)
        ) {
            value
        } else {
            let identifier = value.identifier();
            let some_ptr = self.cache.borrow().get(&identifier).cloned();
            let ptr = if let Some(ptr) = some_ptr {
                ptr
            } else {
                let v = self.push(&Scalar {
                    loader: self.clone(),
                    value,
                });
                let ptr = self.allocate(0x20);
                self.code.borrow_mut().runtime_append(format!("mstore({ptr:#x}, {v})"));
                self.cache.borrow_mut().insert(identifier, ptr);
                ptr
            };
            Value::Memory(ptr)
        };
        Scalar {
            loader: self.clone(),
            value,
        }
    }

    fn ec_point(self: &Rc<Self>, value: Value<(U256, U256)>) -> EcPoint {
        EcPoint {
            loader: self.clone(),
            value: value,
        }
    }

    pub fn keccak256(self: &Rc<Self>, ptr: usize, len: usize) -> usize {
        let hash_ptr = self.allocate(0x20);
        let code = format!("mstore({hash_ptr:#x}, keccak256({ptr:#x}, {len}))");
        self.code.borrow_mut().runtime_append(code);
        hash_ptr
    }

    pub fn copy_scalar(self: &Rc<Self>, scalar: &Scalar, ptr: usize) {
        let scalar = self.push(scalar);
        self.code.borrow_mut().runtime_append(format!("mstore({ptr:#x}, {scalar})"));
    }

    pub fn dup_scalar(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        let ptr = self.allocate(0x20);
        self.copy_scalar(scalar, ptr);
        self.scalar(Value::Memory(ptr))
    }

    pub fn dup_ec_point(self: &Rc<Self>, value: &EcPoint) -> EcPoint {
        let ptr = self.allocate(0x40);
        match value.value {
            Value::Constant((x, y)) => {
                let x_ptr = ptr;
                let y_ptr = ptr + 0x20;
                let code = format!("mstore({x_ptr:#x}, {x})
                    mstore({y_ptr:#x}, {y})");
                self.code.borrow_mut().runtime_append(code);
            }
            Value::Memory(src_ptr) => {
                let x_ptr = ptr;
                let y_ptr = ptr + 0x20;
                let src_x = src_ptr;
                let src_y = src_ptr + 0x20;
                let code = format!("mstore({x_ptr:#x}, mload({src_x:#x}))
                    mstore({y_ptr:#x}, mload({src_y:#x}))");
                self.code.borrow_mut().runtime_append(code);
            }
            Value::Negated(_) | Value::Sum(_, _) | Value::Product(_, _) => {
                unreachable!()
            }
        }
        self.ec_point(Value::Memory(ptr))
    }

    fn staticcall(self: &Rc<Self>, precompile: Precompiled, cd_ptr: usize, rd_ptr: usize) {
        let (cd_len, rd_len) = match precompile {
            Precompiled::BigModExp => (0xc0, 0x20),
            Precompiled::Bn254Add => (0x80, 0x40),
            Precompiled::Bn254ScalarMul => (0x60, 0x40),
            Precompiled::Bn254Pairing => (0x180, 0x20),
        };
        let a = precompile as usize;
        let code = format!("success := and(eq(staticcall(gas(), {a:#x}, {cd_ptr:#x}, {cd_len}, {rd_ptr:#x}, {rd_len}), 1), success)");
        self.code.borrow_mut().runtime_append(code);
    }

    fn invert(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        let rd_ptr = self.allocate(0x20);
        let [cd_ptr, ..] = [
            &self.scalar(Value::Constant(0x20.into())),
            &self.scalar(Value::Constant(0x20.into())),
            &self.scalar(Value::Constant(0x20.into())),
            scalar,
            &self.scalar(Value::Constant(self.scalar_modulus - 2)),
            &self.scalar(Value::Constant(self.scalar_modulus)),
        ]
        .map(|value| self.dup_scalar(value).ptr());
        self.staticcall(Precompiled::BigModExp, cd_ptr, rd_ptr);
        self.scalar(Value::Memory(rd_ptr))
    }

    fn ec_point_add(self: &Rc<Self>, lhs: &EcPoint, rhs: &EcPoint) -> EcPoint {
        let rd_ptr = self.dup_ec_point(lhs).ptr();
        self.dup_ec_point(rhs);
        self.staticcall(Precompiled::Bn254Add, rd_ptr, rd_ptr);
        self.ec_point(Value::Memory(rd_ptr))
    }

    fn ec_point_scalar_mul(self: &Rc<Self>, ec_point: &EcPoint, scalar: &Scalar) -> EcPoint {
        let rd_ptr = self.dup_ec_point(ec_point).ptr();
        self.dup_scalar(scalar);
        self.staticcall(Precompiled::Bn254ScalarMul, rd_ptr, rd_ptr);
        self.ec_point(Value::Memory(rd_ptr))
    }

    pub fn pairing(
        self: &Rc<Self>,
        lhs: &EcPoint,
        g2: (U256, U256, U256, U256),
        rhs: &EcPoint,
        minus_s_g2: (U256, U256, U256, U256),
    ) {
        let rd_ptr = self.dup_ec_point(lhs).ptr();
        let g2_0 = hex_encode_u256(&g2.0);
        let g2_0_ptr = rd_ptr + 0x40;
        let g2_1 = hex_encode_u256(&g2.1);
        let g2_1_ptr = rd_ptr + 0x60;
        let g2_2 = hex_encode_u256(&g2.2);
        let g2_2_ptr = rd_ptr + 0x80;
        let g2_3 = hex_encode_u256(&g2.3);
        let g2_3_ptr = rd_ptr + 0xa0;
        self.allocate(0x80);
        let code = format!("mstore({g2_0_ptr:#x}, {g2_0})
            mstore({g2_1_ptr:#x}, {g2_1})
            mstore({g2_2_ptr:#x}, {g2_2})
            mstore({g2_3_ptr:#x}, {g2_3})");
        self.code.borrow_mut().runtime_append(code);
        self.dup_ec_point(rhs);
        self.allocate(0x80);
        let minus_s_g2_0 = hex_encode_u256(&minus_s_g2.0);
        let minus_s_g2_0_ptr = rd_ptr + 0x100;
        let minus_s_g2_1 = hex_encode_u256(&minus_s_g2.1);
        let minus_s_g2_1_ptr = rd_ptr + 0x120;
        let minus_s_g2_2 = hex_encode_u256(&minus_s_g2.2);
        let minus_s_g2_2_ptr = rd_ptr + 0x140;
        let minus_s_g2_3 = hex_encode_u256(&minus_s_g2.3);
        let minus_s_g2_3_ptr = rd_ptr + 0x160;
        let code = format!("mstore({minus_s_g2_0_ptr:#x}, {minus_s_g2_0})
            mstore({minus_s_g2_1_ptr:#x}, {minus_s_g2_1})
            mstore({minus_s_g2_2_ptr:#x}, {minus_s_g2_2})
            mstore({minus_s_g2_3_ptr:#x}, {minus_s_g2_3})");
        self.code.borrow_mut().runtime_append(code);
        self.staticcall(Precompiled::Bn254Pairing, rd_ptr, rd_ptr);
        let code = format!("success := and(eq(mload({rd_ptr:#x}), 1), success)");
        self.code.borrow_mut().runtime_append(code);
    }

    fn add(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if let (Value::Constant(lhs), Value::Constant(rhs)) = (&lhs.value, &rhs.value) {
            let out = (U512::from(lhs) + U512::from(rhs)) % U512::from(self.scalar_modulus);
            return self.scalar(Value::Constant(out.try_into().unwrap()));
        }

        self.scalar(Value::Sum(
            Box::new(lhs.value.clone()),
            Box::new(rhs.value.clone()),
        ))
    }

    fn sub(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if rhs.is_const() {
            return self.add(lhs, &self.neg(rhs));
        }

        self.scalar(Value::Sum(
            Box::new(lhs.value.clone()),
            Box::new(Value::Negated(Box::new(rhs.value.clone()))),
        ))
    }

    fn mul(self: &Rc<Self>, lhs: &Scalar, rhs: &Scalar) -> Scalar {
        if let (Value::Constant(lhs), Value::Constant(rhs)) = (&lhs.value, &rhs.value) {
            let out = (U512::from(lhs) * U512::from(rhs)) % U512::from(self.scalar_modulus);
            return self.scalar(Value::Constant(out.try_into().unwrap()));
        }

        self.scalar(Value::Product(
            Box::new(lhs.value.clone()),
            Box::new(rhs.value.clone()),
        ))
    }

    fn neg(self: &Rc<Self>, scalar: &Scalar) -> Scalar {
        if let Value::Constant(constant) = scalar.value {
            return self.scalar(Value::Constant(self.scalar_modulus - constant));
        }

        self.scalar(Value::Negated(Box::new(scalar.value.clone())))
    }
}

#[cfg(test)]
impl EvmYulLoader {
    fn start_gas_metering(self: &Rc<Self>, identifier: &str) {
        
    }

    fn end_gas_metering(self: &Rc<Self>) {
        
    }

    pub fn print_gas_metering(self: &Rc<Self>, costs: Vec<u64>) {
        for (identifier, cost) in self.gas_metering_ids.borrow().iter().zip(costs) {
            println!("{}: {}", identifier, cost);
        }
    }
}

#[derive(Clone)]
pub struct EcPoint {
    loader: Rc<EvmYulLoader>,
    value: Value<(U256, U256)>,
}

impl EcPoint {
    pub(crate) fn loader(&self) -> &Rc<EvmYulLoader> {
        &self.loader
    }

    pub(crate) fn value(&self) -> Value<(U256, U256)> {
        self.value.clone()
    }

    pub(crate) fn ptr(&self) -> usize {
        match self.value {
            Value::Memory(ptr) => ptr,
            _ => unreachable!(),
        }
    }
}

impl Debug for EcPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPoint")
            .field("value", &self.value)
            .finish()
    }
}

impl PartialEq for EcPoint {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<C> LoadedEcPoint<C> for EcPoint
where
    C: CurveAffine,
    C::ScalarExt: PrimeField<Repr = [u8; 0x20]>,
{
    type Loader = Rc<EvmYulLoader>;

    fn loader(&self) -> &Rc<EvmYulLoader> {
        &self.loader
    }

    fn multi_scalar_multiplication(pairs: impl IntoIterator<Item = (Scalar, EcPoint)>) -> Self {
        pairs
            .into_iter()
            .map(|(scalar, ec_point)| match scalar.value {
                Value::Constant(constant) if constant == U256::one() => ec_point,
                _ => ec_point.loader.ec_point_scalar_mul(&ec_point, &scalar),
            })
            .reduce(|acc, ec_point| acc.loader.ec_point_add(&acc, &ec_point))
            .unwrap()
    }
}

impl<C> EcPointLoader<C> for Rc<EvmYulLoader>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    type LoadedEcPoint = EcPoint;

    fn ec_point_load_const(&self, value: &C) -> EcPoint {
        let coordinates = value.coordinates().unwrap();
        let [x, y] = [coordinates.x(), coordinates.y()]
            .map(|coordinate| U256::from_little_endian(coordinate.to_repr().as_ref()));
        self.ec_point(Value::Constant((x, y)))
    }

    fn ec_point_assert_eq(&self, _: &str, _: &EcPoint, _: &EcPoint) -> Result<(), Error> {
        unimplemented!()
    }
}

impl<F: PrimeField<Repr = [u8; 0x20]>> ScalarLoader<F> for Rc<EvmYulLoader> {
    type LoadedScalar = Scalar;

    fn load_const(&self, value: &F) -> Scalar {
        self.scalar(Value::Constant(fe_to_u256(*value)))
    }

    fn assert_eq(&self, _: &str, _: &Scalar, _: &Scalar) -> Result<(), Error> {
        unimplemented!()
    }
}

impl<C> Loader<C> for Rc<EvmYulLoader>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    #[cfg(test)]
    fn start_cost_metering(&self, identifier: &str) {
        self.start_gas_metering(identifier)
    }

    #[cfg(test)]
    fn end_cost_metering(&self) {
        self.end_gas_metering()
    }
}
