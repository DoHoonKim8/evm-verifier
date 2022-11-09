use crate::util::arithmetic::MultiMillerLoop;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub struct KzgDecidingKey<M: MultiMillerLoop> {
    pub g2: M::G2Affine,
    pub s_g2: M::G2Affine,
    _marker: PhantomData<M>,
}

impl<M: MultiMillerLoop> KzgDecidingKey<M> {
    pub fn new(g2: M::G2Affine, s_g2: M::G2Affine) -> Self {
        Self {
            g2,
            s_g2,
            _marker: PhantomData,
        }
    }
}

impl<M: MultiMillerLoop> From<(M::G2Affine, M::G2Affine)> for KzgDecidingKey<M> {
    fn from((g2, s_g2): (M::G2Affine, M::G2Affine)) -> KzgDecidingKey<M> {
        KzgDecidingKey::new(g2, s_g2)
    }
}

mod evm {
    use crate::{
        loader::{
            evm::{yulloader::Value, EvmYulLoader},
            LoadedScalar,
        },
        pcs::{
            kzg::{Kzg, KzgAccumulator, KzgDecidingKey},
            Decider,
        },
        util::{
            arithmetic::{CurveAffine, MultiMillerLoop, PrimeField},
            msm::Msm,
        },
    };
    use ethereum_types::U256;
    use std::{fmt::Debug, rc::Rc};

    impl<M, MOS> Decider<M::G1Affine, Rc<EvmYulLoader>> for Kzg<M, MOS>
    where
        M: MultiMillerLoop,
        M::Scalar: PrimeField<Repr = [u8; 0x20]>,
        MOS: Clone + Debug,
    {
        type DecidingKey = KzgDecidingKey<M>;
        type Output = ();

        fn decide(
            dk: &Self::DecidingKey,
            KzgAccumulator { lhs, rhs }: KzgAccumulator<M::G1Affine, Rc<EvmYulLoader>>,
        ) {
            let loader = lhs.loader();
            let [g2, minus_s_g2] = [dk.g2, -dk.s_g2].map(|ec_point| {
                let coordinates = ec_point.coordinates().unwrap();
                let x = coordinates.x().to_repr();
                let y = coordinates.y().to_repr();
                (
                    U256::from_little_endian(&x.as_ref()[32..]),
                    U256::from_little_endian(&x.as_ref()[..32]),
                    U256::from_little_endian(&y.as_ref()[32..]),
                    U256::from_little_endian(&y.as_ref()[..32]),
                )
            });
            loader.pairing(&lhs, g2, &rhs, minus_s_g2);
        }

        fn decide_all(
            dk: &Self::DecidingKey,
            mut accumulators: Vec<KzgAccumulator<M::G1Affine, Rc<EvmYulLoader>>>
        ) {
            assert!(!accumulators.is_empty());

            let accumulator = if accumulators.len() == 1 {
                accumulators.pop().unwrap()
            } else {
                let loader = accumulators[0].lhs.loader();
                let (lhs, rhs) = accumulators
                    .iter()
                    .map(|KzgAccumulator { lhs, rhs }| {
                        let [lhs, rhs] = [&lhs, &rhs].map(|ec_point| loader.dup_ec_point(ec_point));
                        (lhs, rhs)
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();

                let hash_ptr = loader.keccak256(lhs[0].ptr(), lhs.len() * 0x80);
                let challenge_ptr = loader.allocate(0x20);
                let code =
                    format!("mstore({challenge_ptr}, mod(mload({hash_ptr}), f_q))");
                loader.code_mut().runtime_append(code);
                let challenge = loader.scalar(Value::Memory(challenge_ptr));

                let powers_of_challenge = LoadedScalar::<M::Scalar>::powers(&challenge, lhs.len());
                let [lhs, rhs] = [lhs, rhs].map(|msms| {
                    msms.into_iter()
                        .zip(powers_of_challenge.iter())
                        .map(|(msm, power_of_challenge)| {
                            Msm::<M::G1Affine, Rc<EvmYulLoader>>::base(msm) * power_of_challenge
                        })
                        .sum::<Msm<_, _>>()
                        .evaluate(None)
                });

                KzgAccumulator::new(lhs, rhs)
            };

            Self::decide(dk, accumulator);
        }
    }
}
