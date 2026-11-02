#!/bin/sh

set -e

if [ -z "$1" ] && [ -z "$SSLKEYLOGFILE" ]; then
  echo "Warning: no SSLKEYLOGFILE given, SSL keys will not be logged"
elif [ -n "$1" ]; then
  export SSLKEYLOGFILE="$1"
fi

cargo build

# Run the given cargo binary (either 'client' or 'server'), special handling to always run the server in the background.
# Also changes the output to clearly indicate which binary it is from.
run() {
  server_client="$1"
  shift 1
  set -- cargo run --quiet --bin "$server_client" -- "$@"
  echo "$@"

  case "$server_client" in
    server)
      ("$@" | sed "s/^/[$server_client] /") &
      ;;
    client)
      "$@" | sed "s/^/[$server_client] /"
      ;;
    *)
      echo "Unknown binary for cargo run: $server_client, aborting..";
      exit 2
  esac
}

# Run the given cargo binary (either 'client' or 'server') with the --keyt] /") and --cert argument set.
# Calls run()
run_with_cert() {
  server_client="$1"
  cert_no="$2"
  shift 2

  case "$server_client" in
    server)
      cert_base_no=0
      ;;
    client)
      cert_base_no=2012
      ;;
    *)
      echo "Unknown binary for cargo run: $server_client, aborting..";
      exit 2
  esac

  run "$server_client" --key ./keys/"$server_client".pem --cert ./certs/cert_"$cert_base_no"_"$cert_no".pem "$@"
}

# without MTLS
cat <<EOT
###################
# Only server TLS #
###################
EOT

# simple
echo "Simple"
run_with_cert server 0
run client
wait
echo

# multi cosigners
echo "Multiple cosigners"
run_with_cert server 1
run client --cosigner ./cosigner.json
wait
echo

# landmark cert
echo "Landmark cert"
run_with_cert server 2
run client --landmarks 1:./landmarks.txt
wait
echo

# MTLS
cat <<EOT

##############
# Mutual TLS #
##############
EOT

run_mtls() {
  # program name, either "server" or "client"
  name="$1"
  # If $name is "server", set $server_opt here.
  # If $name is "client", set $client_opt here.
  opt1="$2"
  # If $name is "server", set $client_opt here.
  # If $name is "client", set $server_opt here.
  opt2="$3"
  shift 3
  # rest are the base options to use when running

  # set parameters based on the options value for this program (server or client)
  case "$opt1" in
    "simple")
      cert=0
      ;;
    "multiple cosigners")
      cert=1
      ;;
    "landmark cert")
      cert=2
      ;;
    *)
      echo "Unknown configuration value: $opt1, aborting..."
      exit 3
      ;;
  esac

  # set base command
  set -- run_with_cert "$name" "$cert" "$@"

  # run with parameters based on the options value for the other program
  case "$opt2" in
    "simple")
      "$@"
      ;;
    "multiple cosigners")
      "$@" --cosigner ./cosigner.json
      ;;
    "landmark cert")
      "$@" --landmarks 1:./landmarks.txt
      ;;
    *)
      echo "Unknown configuration value: $opt2, aborting..."
      exit 3
      ;;
  esac
}

for server_opt in "simple" "multiple cosigners" "landmark cert"; do
  for client_opt in "simple" "multiple cosigners" "landmark cert"; do
    echo "Server: $server_opt, Client: $client_opt"

    # start the server
    run_mtls server "$server_opt" "$client_opt" --client-auth
    # run the client
    run_mtls client "$client_opt" "$server_opt"

    wait
    echo
  done
done