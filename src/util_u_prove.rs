use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as ScalarField;
use rand::rngs::ThreadRng;
pub struct PublicParams {
    pub g0: RistrettoPoint,
    pub gxt: RistrettoPoint,
    pub gd: RistrettoPoint,
}

pub fn setup(rng: &mut ThreadRng) -> PublicParams {
    let g0 = RistrettoPoint::random(rng);
    let gt = RistrettoPoint::random(rng);
    let gd = RistrettoPoint::random(rng); 
    
    let xt = ScalarField::random(rng);
    let gxt = &g0 + &xt * &gt;

    let pp = PublicParams{g0, gxt, gd};
    return pp
}

pub struct InitMessage {
    pub Sigma_z: RistrettoPoint,
    pub Sigma_a: RistrettoPoint,
    pub Sigma_b: RistrettoPoint,
}

pub struct Token {
    pub H: RistrettoPoint,
    pub pi: ScalarField,
    pub Sigma_z_: RistrettoPoint,
    pub sigma_c_: ScalarField,
    pub sigma_r_: ScalarField
}

pub struct Witness {
    pub alpha: ScalarField
}

pub struct RedemptionProof1 {
    pub token: Token,
    pub comm: RistrettoPoint
}

pub struct RedemptionProof2 {
    pub r0: ScalarField,
    pub rd: ScalarField
}