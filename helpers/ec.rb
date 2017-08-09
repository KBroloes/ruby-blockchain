require 'openssl'

def ec_generate
  ec = OpenSSL::PKey::EC.new('secp256k1');

  ec.generate_key

  pkey = ec.private_key.to_s 16 # Returns BigNum, convert to base16 (hex)
  pubkey = ec.public_key.to_bn.to_s 16 # Convert to BigNum so we can get the hex value

  puts "Keypair:"
  puts "Priv: #{pkey}"
  puts "Publ: #{pubkey}"

  pretty_print_pubkey pubkey

  return pkey, pubkey
end

def pretty_print_pubkey(pubkey)
  i = 2
  blocksize = 32 * 2
  type = 2

  puts "\nType: #{pubkey[0] + pubkey[1]} (02 compressed, 04 uncompressed)"
  x = ""
  y = ""
  while i < pubkey.size do
    x += pubkey[i] unless i >= blocksize + type
    y += pubkey[i] unless i < blocksize + type
    i = i+1
  end

  puts "x: #{x}, size: #{x.size / 2}"
  puts "y: #{y}, size: #{y.size / 2}"
end