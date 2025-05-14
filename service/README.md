# BTC Light Client Server

Mainly two components:

- **Consensus Server**, which runs backend as a daemon program

- **Execution Server**, which runs frontend as general HTTP server, accepting connection outside, it will accept two kinds of HTTP request:

  - **POST Prove Job**, it will launch a new separate task to process POST prove job, runs backend and save prove result into somewhere

  - **GET Prove Result**, it will try to access prove result and return it

Run command:

```shell
RUST_LOG=info cargo run --bin btc_light_client_server -—release -— https://bitcoin-mainnet.public.blastapi.io 852800 ./data/consensus 8080
```

---

# HTTP API

#### POST Prove Job

```shell
curl -H "Accept: application/json" -X POST http://127.0.0.1:8080/post_prove_job?txid=32f007715010e49a70059e95a451ddaf36c0d2d93819cbd54b2e8758ef36e4b5
```

#### GET Prove Result

```shell
curl -G -d "txid=32f007715010e49a70059e95a451ddaf36c0d2d93819cbd54b2e8758ef36e4b5" -H "Accept: application/json" http://127.0.0.1:8080/get_prove_result
```

## Run a Bitcoind Node

```bash
docker run \
  -v ${HOME}/.bitcoin/signet:/home/bitcoin/.bitcoin \
  -d \
  --name bitcoin-signet \
  -p 38332:38332 \
  -p 38333:38333 \
  bitcoin/bitcoin:28.0 \
  -printtoconsole \
  -signet=1 \
  -rest \
  -rpcbind=0.0.0.0 \
  -rpcallowip=0.0.0.0/0 \
  -rpcport=38332 \
  -rpcuser=btc_lc \
  -rpcpassword=btc_lc \
  -server \
  -txindex=1 \
  -rpcauth='btc_lc:f401f2e8f6d7347156497860e048aa3b$2be5208f969a4b947892006e0bdc0d7bf49c4b8bd232322e9ed9cf3685573736'
```

