# fipscryptor.rb - simple Ruby encryptor using OpenSSL FIPS mode
# Author: Sandy Cash <lhcash@us.ibm.com>

require 'openssl'
require 'base64'

class Fipscryptor
	class << self
		ALGORITHM = 'AES-256-CFB'

		# Generate a PKCS5 encryption key with some reasonable defaults
		def generate_key(passphrase, salt)
	    	iter = 200000
	    	key_len = 32
	    	OpenSSL::PKCS5.pbkdf2_hmac_sha1(passphrase, salt, iter, key_len)
	    end

	 	# def generate_key(passphrase, salt)
	 		# return nil unless ( passphrase && salt )
	 		# passphrase
	 	# end

	 	# Return a random sequence of eight bytes
	 	def generate_salt
	 		OpenSSL::Random.random_bytes(8).to_s
	 	end

	 	# Return a random sequence of at least 16 bytes and at most 186 bytes
	 	# The maximum is to ensure that the base64-encoded length is <= 256
	 	def generate_iv(len)
	 		if (len < 16)
	 			len = 16
	 		elsif (len > 186)
	 			len = 186
	 		end

	 		OpenSSL::Random.random_bytes(len).to_s
	 	end

	 	def generate_cipher(algo)
	 		unless algo
	 			algo = ALGORITHM
	 		end

	 		OpenSSL::Cipher.new(algo)
	 	end

	 	def encrypt(cipher, plaintext, key, iv)
	 		cipher.reset
	 		cipher.encrypt
	 		cipher.key=(key)
	 		cipher.iv=(iv)
	 		cipher.update(plaintext).tap { |output| output << cipher.final }
	 	end

	 	# Return the base64-encoded join of iv.length+iv+encrypted
	 	# Only works if all IVs have a length <= 186.  This means that the length
	 	# of the base-64 encoded IV will be <= 256, which is a single-byte value.
	 	# (single byte => 4 chars when encoded)
	 	def encrypt_and_package(cipher, plaintext, key, iv)
	 		iv_enc = Base64.strict_encode64(iv)
	 		Base64.strict_encode64(iv_enc.length.to_s).tap { |output| output << iv_enc << encrypt(cipher, plaintext, key, iv) }
	 	end

	 	def decrypt(cipher, encrypted, key, iv)
	 		cipher.reset
	 		cipher.decrypt
	 		cipher.key=(key)
	 		cipher.iv=(iv)
	 		cipher.update(encrypted).tap { |output| output << cipher.final }
	 	end

	 	# First decode the base64-encoded string, trim the iv from the front, then decrypt
	 	def decode_and_decrypt(cipher, encoded, key)
	 		iv_enc_len = Base64.decode64(encoded[0,4]).to_i
			iv = Base64.decode64(encoded[4, iv_enc_len])
			decrypt(cipher, encoded[4 + iv_enc_len, encoded.length - (4 + iv_enc_len)], key, iv)
		end	 		
	end
end