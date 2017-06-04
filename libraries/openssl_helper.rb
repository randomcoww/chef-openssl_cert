module OpenSSLHelper

  class CertGenerator
    attr_reader :dbag

    include Dbag

    def initialize(data_bag, data_bag_item, root_subject)
      @dbag = Dbag::Keystore.new(data_bag, data_bag_item)
      @root_subject = OpenSSL::X509::Name.new(root_subject)
      @root_data_bag_key = Base64.encode64(@root_subject.to_s.chomp)
    end


    def generate_key
      OpenSSL::PKey::RSA.new(2048)
    end

    def root_ca
      return @root_ca unless @root_ca.nil?

      k = get_or_create_dbag("root-ca-#{@root_data_bag_key}") {
        ca = OpenSSL::X509::Certificate.new
        ca.version = 2
        ca.serial = 1

        ca.subject = @root_subject
        ca.issuer = ca.subject
        ca.public_key = root_key.public_key

        ca.not_before = Time.new
        ca.not_after = ca.not_before + 63072000

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = ca
        ef.issuer_certificate = ca
        ca.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
        ca.add_extension(ef.create_extension("keyUsage", "keyCertSign, cRLSign", true))
        ca.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
        ca.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always", false))

        ca.sign(root_key, OpenSSL::Digest::SHA256.new)
        ca.to_pem
      }

      @root_ca = OpenSSL::X509::Certificate.new(k)
    end


    def node_cert(subject, key, extensions={}, alt_names={})
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2

      cert.subject = OpenSSL::X509::Name.new(subject)
      cert.issuer = root_ca.subject
      cert.public_key = key.public_key

      cert.not_before = Time.new
      cert.not_after = cert.not_before + 63072000

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = root_ca
      ef.config = OpenSSL::Config.load(OpenSSL::Config::DEFAULT_CONFIG_FILE)

      if !alt_names.empty?
        ef.config['alt_names'] = alt_names
        extensions['subjectAltName'] = '@alt_names'
      end

      extensions.each_pair do |k, v|
        cert.add_extension(ef.create_extension(k, v, true))
      end

      cert.sign(root_key, OpenSSL::Digest::SHA256.new)
      return cert
    end


    private

    def root_key
      return @root_key unless @root_key.nil?

      k = get_or_create_dbag("root-ca-#{@root_data_bag_key}-key") {
        generate_key.to_pem
      }

      @root_key = OpenSSL::PKey::RSA.new(k)
    end

    def get_or_create_dbag(key)
      value = dbag.get(key)

      return value unless value.nil?

      value = yield
      dbag.put(key, value)

      return value
    end
  end
end
