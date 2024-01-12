use criterion::{criterion_group, criterion_main, Criterion};


fn criterion_benchmark_u_prove(c: &mut Criterion) {

    use curve25519_dalek_ng::ristretto::RistrettoPoint;
    use curve25519_dalek_ng::scalar::Scalar as ScalarField;
    use rand::rngs::ThreadRng;

    use ntat::server_u_prove::*;
    use ntat::client_u_prove::*;
    use ntat::util_u_prove::*;

    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);

    // Client KeyGen
    let sk_c = ScalarField::random(&mut rng);
    let pk_c = pp.gd * sk_c;

    // Server KeyGen
    let sk_s = ScalarField::random(&mut rng);
    let pk_s = pp.g0 * sk_s.invert();

    let pi = ScalarField::random(&mut rng);
    let rand_state = ScalarField::random(&mut rng);
    let mut client = Client::new(&pp, sk_c, pk_c, pi, rand_state);
    let mut server = Server::new(&pp, pk_c, sk_s, pk_s, rand_state);

    c.bench_function("Server Initiate U-Prove", |b| b.iter(|| server.server_initiate(&mut rng, &pp)));
    let message = server.server_initiate(&mut rng, &pp);

    c.bench_function("Client Query U-Prove", |b| b.iter(|| client.client_query(&mut rng, &pp, pk_s, &message)));
    let sigma_c = client.client_query(&mut rng, &pp, pk_s, &message);

    c.bench_function("Server Issue U-Prove", |b| b.iter(|| server.server_issue(sigma_c)));
    let sigma_r = server.server_issue(sigma_c);

    c.bench_function("Client Final U-Prove", |b| b.iter(|| server.server_initiate(&mut rng, &pp)));
    let token = client.client_final(&pp, pk_s, sigma_r);

    let (token, witness) = token.unwrap();

    c.bench_function("Client Prove Redemption1 U-Prove", |b| b.iter(|| client.client_prove_redemption1(&mut rng, &pp, &token)));
    let proof1 = client.client_prove_redemption1(&mut rng, &pp, &token);

    c.bench_function("Server Verify Redemption1 U-Prove", |b| b.iter(|| server.server_verify_redemption1(&mut rng, &pp, &proof1)));
    let a = server.server_verify_redemption1(&mut rng, &pp, &proof1);
    let a = a.unwrap();

    c.bench_function("Client Prove Redemption2 U-Prove", |b| b.iter(|| client.client_prove_redemption2(&token, a)));
    let proof2 = client.client_prove_redemption2(&token, a);

    c.bench_function("Server Verify Redemption2 U-Prove", |b| b.iter(|| server.server_verify_redemption2(&token, &pp, &proof2)));
    let verified = server.server_verify_redemption2(&token, &pp, &proof2);

    assert_eq!(verified, true);

}



//criterion_group!(benches, criterion_benchmark_dalek, criterion_benchmark_pairing, criterion_benchmark_u_prove);
criterion_group!(benches, criterion_benchmark_u_prove);
criterion_main!(benches);