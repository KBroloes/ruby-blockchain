require 'openssl'

class EllipticCurve
  UNCOMPRESSED = '04'
  COMP_EVEN = '02'
  COMP_ODD = '03'

  attr_reader :pkey, :pub

  def initialize
    ec = OpenSSL::PKey::EC.new('secp256k1')

    ec.generate_key

    @pkey = ec.private_key.to_s 16 # Returns BigNum, convert to base16 (hex)
    @pub = ec.public_key.to_bn.to_s 16 # Convert to BigNum so we can get the hex value
  end

  def get_components(pub)
    block_size = 32 * 2  # 32 bytes in hex
    type_size = 2        # 1 byte in hex

    key = pub.split(//) # Convert to char array
    {
        :type => key.take(type_size).join,
        :x => key.drop(type_size).take(block_size).join,
        :y => key.drop(type_size + block_size).take(block_size).join
    }
  end

  def get_compressed(pub)
    key = pub.split(//) # Convert to char array
    x = key.drop(2).take(64).join

    # No reason to send the whole number for testing
    y_ending = key.drop(2 + 64 + 63).join

    get_prefix(y_ending) + x
  end

  def get_prefix(key)
    (key.hex() % 2) != 0 ? COMP_ODD : COMP_EVEN
  end
end
