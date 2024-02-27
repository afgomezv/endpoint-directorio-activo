const ldap = require("ldapjs");
const dotenv = require("dotenv");

dotenv.config();

const ldapUrl = process.env.LDAP_URL || process.env.LDAP_URL2;
const baseDn = process.env.LDAP_BASE_DN;
const adminDn = process.env.LDAP_ADMIN_DN;
const adminPassword = process.env.LDAP_ADMIN_PASSWORD;

const getLdapClient = () => {
  const client = ldap.createClient({
    url: ldapUrl,
  });

  client.on("error", (err) => {
    console.error("Error en el cliente LDAP:", err);
  });

  client.bind(adminDn, adminPassword, (err) => {
    if (err) {
      console.error("Error de conexión: ", err);
    } else {
      console.log("Conexión exitosa!");
    }
  });

  return client;
};

module.exports = {
  getLdapClient,
};
