use curve25519_dalek_ng::{ristretto::RistrettoPoint, traits::MultiscalarMul};
use curve25519_dalek_ng::scalar::Scalar as ScalarField;
use rand::rngs::ThreadRng;
use sha2::{Digest, Sha256};

use crate::util_u_prove::{PublicParams, Token, Witness, InitMessage, RedemptionProof1, RedemptionProof2};


pub struct Client {
    pub pp: PublicParams,
    pub sk_c: ScalarField,
    pub pk_c: RistrettoPoint,
    pub pi: ScalarField, // prover information
    pub H: RistrettoPoint,
    pub alpha: ScalarField,
    pub beta2: ScalarField,
    pub sigma_c_: ScalarField,
    pub Sigma_z_: RistrettoPoint,
    pub Sigma_a_: RistrettoPoint,
    pub Sigma_b_: RistrettoPoint,
    pub wd_: ScalarField,
    pub w0: ScalarField,
    pub wd: ScalarField
}


impl Client {
    pub fn new(pp: &PublicParams, sk_c: ScalarField , pk_c: RistrettoPoint, pi: ScalarField, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set w to random state
        let client_pp = PublicParams{g0: pp.g0, gxt: pp.gxt, gd: pp.gd};
        let rand_g = pp.g0;
        Client { pp: client_pp, sk_c, pk_c, pi: st, H: rand_g, alpha: st, beta2: st, sigma_c_: st, Sigma_z_: rand_g, Sigma_a_: rand_g, Sigma_b_: rand_g, wd_: st, w0: st, wd: st }
    }

    pub fn client_query(
        &mut self,
        rng: &mut ThreadRng,
        pp: &PublicParams,
        Y: RistrettoPoint,
        init_message: &InitMessage ) -> ScalarField {
        
        let alpha = ScalarField::random(rng);
        self.alpha = alpha; // update state for future use.
        let beta1 = ScalarField::random(rng);
        let beta2 = ScalarField::random(rng);
        self.beta2 = beta2; //update state for future use.
        let H = (pp.gxt + self.pk_c) * alpha;
        self.H = H; // update state for future use.
        let Sigma_z_ = init_message.Sigma_z * alpha;
        // let Sigma_a_ = pp.g0 * beta1 + Y * beta2 + init_message.Sigma_a;
        let Sigma_a_ = RistrettoPoint::multiscalar_mul([beta1, beta2, ScalarField::one()], [pp.g0, Y, init_message.Sigma_a]);
        //let Sigma_b_ = Sigma_z_ * beta1 + H * beta2 + init_message.Sigma_b * alpha;
        let Sigma_b_ = RistrettoPoint::multiscalar_mul([beta1, beta2, alpha], [Sigma_z_, H, init_message.Sigma_b]);
        self.Sigma_z_ = Sigma_z_;
        self.Sigma_a_ = Sigma_a_;
        self.Sigma_b_ = Sigma_b_;

        let mut h = Sha256::new();

        h.update(&H.compress().to_bytes());
        h.update(&self.pi.to_bytes());
        h.update(&Sigma_z_.compress().to_bytes());
        h.update(&Sigma_a_.compress().to_bytes());
        h.update(&Sigma_b_.compress().to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");

        let sigma_c_ = ScalarField::from_bytes_mod_order(digest);
        self.sigma_c_ = sigma_c_; // update state for future use.

        let sigma_c = sigma_c_ + beta1; 

        return sigma_c;
    }

    pub fn client_final(
        &mut self,
        pp: &PublicParams,
        Y: RistrettoPoint,
        sigma_r: ScalarField ) -> Option<(Token, Witness)> {
        
        let sigma_r_ = sigma_r + self.beta2;

        if self.Sigma_a_ + self.Sigma_b_ != (self.H + Y) * sigma_r_ - (pp.g0 + self.Sigma_z_) * self.sigma_c_ {
            return None;
        }

        return Some((Token{H: self.H, pi: self.pi, Sigma_z_: self.Sigma_z_, sigma_c_: self.sigma_c_, sigma_r_}, Witness{alpha: self.alpha}))
    }

    pub fn client_prove_redemption1(
        &mut self,
        rng : &mut ThreadRng, 
        pp: &PublicParams,
        token: &Token) -> RedemptionProof1 {

        // core
        let wd_ = ScalarField::random(rng);
        //let Ad = wd_ * pp.gd; // handled in msm
        
        // helper
        let w0 = ScalarField::random(rng);
        let wd = ScalarField::random(rng);

        self.wd_ = wd_;
        self.w0 = w0;
        self.wd = wd;

        // let comm = w0 * token.H + wd*pp.gd + Ad; // without msm
        let comm = RistrettoPoint::multiscalar_mul([w0, wd, wd_], [token.H, pp.gd, pp.gd]);
        let tok = Token{H: token.H, pi: token.pi, Sigma_z_: token.Sigma_z_, sigma_c_: token.sigma_c_, sigma_r_: token.sigma_r_};
        return RedemptionProof1 { token: tok, comm};
    }

    pub fn client_prove_redemption2(
        &self,
        token: &Token,
        a: ScalarField) -> RedemptionProof2 {
        
        // helper
        let mut h = Sha256::new();

        h.update(&token.H.compress().to_bytes());
        h.update(&a.to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");

        let c_p = ScalarField::from_bytes_mod_order(digest);

        // core
        let mut h = Sha256::new();
        h.update(&c_p.to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");
        let c = ScalarField::from_bytes_mod_order(digest);

        let rd_ = -c * self.sk_c + self.wd_;

        // helper
        let mut h = Sha256::new();
        h.update(&c_p.to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H");
        let ch = ScalarField::from_bytes_mod_order(digest);

        let r0 = c * self.alpha.invert() + self.w0;
        let rd = rd_ + self.wd;

        return RedemptionProof2 { r0, rd};
    }

}