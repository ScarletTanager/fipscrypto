require_relative '../fipscryptor'

# module Fipscrypto
	describe Fipscryptor do
		before :each do
	# 		# Make sure FIPS mode is really on
	# 		# If your OpenSSL was not built with the FIPS module, this will error and cause
	# 		# rspec to exit
	# 		OpenSSL.fips_mode = true

			@passphrase = 'thisismypassphrase'
			@plaintext = 'for those about to rock'
			# let(:passphrase) { 'thisismypassphrase' }
			# let(:plaintext) { 'for those about to rock' }
			@salt = Fipscryptor.generate_salt
			@key = Fipscryptor.generate_key(@passphrase, @salt)
			@iv_len = 16
			@iv = Fipscryptor.generate_iv(@iv_len)
			# let(:salt) { FIPSCryptor.generate_salt }
			# let(:key) { FIPSCryptor.generate_key(passphrase) }

			@cipher = Fipscryptor.generate_cipher(nil)
		end

		describe "#generate_cipher" do
			it "returns a correct and valid default cipher" do
				expect(@cipher).to be_a(OpenSSL::Cipher)
			end
		end

		describe "#generate_key" do
			it "returns a key of appropriate length different from the passphrase" do
				expect(@key).not_to include(@passphrase)
			end

			it "returns a different key for each passphrase" do
				passphrase = 'thisisadifferentpassphrase'
				key2 = Fipscryptor.generate_key(passphrase, @salt)
				expect(@key).not_to eql(key2)
			end
		end

		describe "#generate_salt" do
			it "returns random, unique salt of the appropriate length" do
				expect(@salt.length).to eql(8)
				expect(@salt).not_to eql(Fipscryptor.generate_salt)
			end
		end

		describe '#generate_iv' do
			it "returns a random, unique iv of appropriate length or greater" do
				expect(@iv.length).to be >= 16
				expect(@iv).not_to eql(Fipscryptor.generate_iv(@iv_len))
			end

			it "adheres to a minimum length of 16 bytes" do
				iv = Fipscryptor.generate_iv(7)
				expect(iv.length).to be >= 16
			end

			it "allows for iv lengths longer than 16 bytes" do
				iv = Fipscryptor.generate_iv(24)
				expect(iv.length).to eql(24)
			end
		end

		describe "#encrypt" do
			it "returns an encrypted string which does not contain the original plaintext" do
				expect(Fipscryptor.encrypt(@cipher, @plaintext, @key, @iv)).not_to include(@plaintext)
			end
		end

		describe "#encrypt_and_package" do
			it "returns a base64-encoded string which begins with the iv" do
				encoded = Fipscryptor.encrypt_and_package(@cipher, @plaintext, @key, @iv)
				iv_enc_len = Base64.decode64(encoded[0,4]).to_i
				iv = Base64.decode64(encoded[4,iv_enc_len])
				expect(iv).to eql(@iv)
			end

			it "works with IVs of different lengths <= 186" do
				iv = Fipscryptor.generate_iv(100)
				encoded = Fipscryptor.encrypt_and_package(@cipher, @plaintext, @key, iv)
				iv_enc_len = Base64.decode64(encoded[0,4]).to_i
				iv_dec = Base64.decode64(encoded[4, iv_enc_len])
				expect(iv_dec).to eql(iv)

				iv = Fipscryptor.generate_iv(186)
				encoded = Fipscryptor.encrypt_and_package(@cipher, @plaintext, @key, iv)
				iv_enc_len = Base64.decode64(encoded[0,4]).to_i
				iv_dec = Base64.decode64(encoded[4, iv_enc_len])
				expect(iv_dec).to eql(iv)

				iv = Fipscryptor.generate_iv(64)
				encoded = Fipscryptor.encrypt_and_package(@cipher, @plaintext, @key, iv)
				iv_enc_len = Base64.decode64(encoded[0,4]).to_i
				iv_dec = Base64.decode64(encoded[4, iv_enc_len])
				expect(iv_dec).to eql(iv)
			end
		end
		
		describe "performing symmetric encryption" do
			describe "#decode_and_decrypt" do
				before :each do
					# Setup an encrypted string
					@encoded = Fipscryptor.encrypt_and_package(@cipher, @plaintext, @key, @iv)
				end

				it "successfully decodes and decrypts the encoded and encrypted string" do
					expect(Fipscryptor.decode_and_decrypt(@cipher, @encoded, @key)).to eql(@plaintext)
				end
			end

			describe "#decrypt" do
				before :each do
					# Setup an encrypted string
					@encrypted = Fipscryptor.encrypt(@cipher, @plaintext, @key, @iv)
				end

				it "successfully decrypts the encrypted string" do
					expect(Fipscryptor.decrypt(@cipher, @encrypted, @key, @iv)).to eql(@plaintext)
				end
			end
		end
	end
# end