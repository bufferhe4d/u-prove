use curve25519_dalek_ng::{ristretto::RistrettoPoint, traits::MultiscalarMul};
use curve25519_dalek_ng::scalar::Scalar as ScalarField;
use rand::rngs::ThreadRng;
use crate::util_u_prove::{PublicParams, Token, Witness, InitMessage, RedemptionProof1, RedemptionProof2};
use sha2::{Digest, Sha256};

pub struct Server {
    pub pp: PublicParams,
    pub pk_c: RistrettoPoint,
    pub w: ScalarField,
    pub sk_s: ScalarField,
    pub pk_s: RistrettoPoint,
    pub a: ScalarField,
    pub comm: RistrettoPoint
}

impl Server {
    pub fn new(pp: &PublicParams, pk_c: RistrettoPoint, sk_s: ScalarField, pk_s: RistrettoPoint, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set w to random state
        let server_pp = PublicParams{g0: pp.g0, gxt: pp.gxt, gd: pp.gd};
        let rand_g = pp.g0;
        Server { pp: server_pp, pk_c, w: st, sk_s, pk_s, a: st, comm: rand_g}
    }

    pub fn server_initiate(&mut self,
        rng: &mut ThreadRng, 
        pp: &PublicParams) -> InitMessage {
    
        let y0 = self.sk_s;
        let gamma = pp.gxt + self.pk_c;
        let Sigma_z = gamma * y0;
        let w = ScalarField::random(rng);
        
        self.w = w; // update state for future use.

        let Sigma_a = self.pk_s * w;
        let Sigma_b = gamma * w;

        InitMessage {Sigma_z, Sigma_a, Sigma_b}
    }

    pub fn server_issue(&self, sigma_c: ScalarField) -> ScalarField {
        return self.sk_s * sigma_c + self.w;
    }

    pub fn server_verify_redemption1(
        &mut self,
        rng: &mut ThreadRng,
        pp: &PublicParams,
        proof: &RedemptionProof1) -> Option<ScalarField> {

        let mut h = Sha256::new();
        h.update(&proof.token.H.compress().to_bytes());
        h.update(&proof.token.pi.to_bytes());
        h.update(&proof.token.Sigma_z_.compress().to_bytes());
        h.update(&(proof.token.sigma_r_ * self.pk_s - proof.token.sigma_c_ * pp.g0).compress().to_bytes());
        h.update(&(proof.token.sigma_r_ * proof.token.H - proof.token.sigma_c_ * proof.token.Sigma_z_).compress().to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");

        let right = ScalarField::from_bytes_mod_order(digest);

        self.comm = proof.comm;
        
        if proof.token.sigma_c_ != right {
            return None
        } else {
            let a = ScalarField::random(rng);
            self.a = a;
            return Some(a);
        }

    }

    pub fn server_verify_redemption2(
        &self,
        token: &Token,
        pp: &PublicParams,
        proof: &RedemptionProof2) -> bool {

        let mut h = Sha256::new();

        h.update(&token.H.compress().to_bytes());
        h.update(&self.a.to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");

        let c_p = ScalarField::from_bytes_mod_order(digest);

        let mut h = Sha256::new();

        h.update(&c_p.to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");

        let c = ScalarField::from_bytes_mod_order(digest);
        
        //let right = -c * pp.gxt + proof.r0 * token.H + proof.rd * pp.gd;
        let right = RistrettoPoint::multiscalar_mul([-c, proof.r0, proof.rd], [pp.gxt, token.H, pp.gd]);
        return self.comm == right;
    }
}