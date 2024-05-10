const express = require("express");
const { getLdapClient } = require("./ladp");

const PORT = process.env.PORT;

const app = express();
//const ldapClient = getLdapClient();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//! Endpoint: verifica la conexion al directorio activo
app.get("/", (req, res) => {
  const ldapClient = getLdapClient();
  ldapClient.unbind();
  res.send("Se conecto directorio activo exitoso!");
});

//! Endpoint: Autenticar usuarios del directorio activo (método POST)
app.post("/auth", (req, res) => {
  const { username, password } = req.body;
  const ldapClient = getLdapClient();

  const opts = {
    filter: `(samAccountName=${username})`,
    scope: "sub",
    attributes: [
      "accountExpires",
    ]
  };

  ldapClient.search(
    "OU=Usuarios,OU=INDER,DC=inder,DC=gov,DC=local",
    opts,
    (err, searchRes) => {
      if (err) {
        //* Error al realizar la búsqueda
        res.status(500).send("Error en la búsqueda del usuario");
        return;
      }

      let userFound = false;

      searchRes.on("searchEntry", (entry) => {
        //* Se encontró un usuario en el directorio activo
        userFound = true;
        const userDn = entry.dn.toString();
        const userData = entry.pojo.attributes;

        //* Verificar si 'userData' contiene el atributo 'accountExpires'
        if (userData && userData.length > 0 && userData[0].type === 'accountExpires' && userData[0].values.length > 0) {
          //* Leer el valor de 'accountExpires'
          const accountExpires = parseInt(userData[0].values[0]);
          //console.log("accountExpires", accountExpires);

          //* Convertir el valor a una fecha
          const accountExpiresDate = new Date((accountExpires/10000) - 11644473600000);
          //console.log("accountExpiresDate", accountExpiresDate);
          
          //* Obtener la fecha actual
          const currentDate = new Date();
          
          if(accountExpires !== 0 && currentDate > accountExpiresDate){
            res.status(401).send("La cuenta ha expirado");
            return;
          }
        }

        //* Autenticar al usuario utilizando su contraseña
        authenticateUser(ldapClient, userDn, password, (authErr) => {
          if (authErr) {
            //* La autenticación ha fallado
            res.status(401).send("Contraseña incorrecta");
          } else {
            //* La autenticación ha sido exitosa
            res.status(200).send("Autenticación exitosa");
          }
        });
      });

      //* Error en la búsqueda del usuario
      searchRes.on("error", (error) => {
        res.status(500).send("Error en la búsqueda del usuario");
      });

      //* No se encontró ningún usuario en el directorio activo
      searchRes.on("end", () => {
        if (!userFound) {
          res.status(404).send("Usuario no encontrado");
        }
      });
    }
  );
});


function authenticateUser(ldapClient, userDn, password, callback) {
  ldapClient.bind(userDn, password, (bindErr) => {
    callback(bindErr);
  });
}


//! Endpoint para autenticar usuarios y traer todos sus valores (método POST)
app.post("/auth/:username", (req, res) => {
  const username = req.params.username;
  const password = req.body.password;
  const ldapClient = getLdapClient();

  const opts = {
    filter: `(samAccountName=${username})`,
    scope: "sub",
    attributes: [
      "accountExpires",
      "cn",
      "title",
      "description",
      "physicalDeliveryOfficeName",
      "givenName",
      "department",
      "mailNickname",
      "employeeType",
      "employeeID",
      "userParameters",
    ]
  };

  ldapClient.search(
    "OU=Usuarios,OU=INDER,DC=inder,DC=gov,DC=local",
    opts,
    (err, searchRes) => {
      if (err) {
        //* Error al realizar la búsqueda
        res.status(500).send("Error en la búsqueda del usuario");
      } else {
        let userFound = false;

        searchRes.on("searchEntry", (entry) => {
          //* Se encontró un usuario en el directorio activo
          userFound = true;
          const userDn = entry.dn.toString();
          const userData = entry.pojo.attributes;

         
          function getAccountExpires(userData){
            const accountExpiresObj = userData.find(obj => obj.type === 'accountExpires')
            if(accountExpiresObj){
              return accountExpiresObj.values[0]
            }else{
              return null
            }
          }

          const givenAccountValue = getAccountExpires(userData)
          console.log("givenAccountValue", givenAccountValue);
          
          if (userData && userData.length > 0) {
            //* Leer el valor de 'accountExpires'
            
            const accountExpires = parseInt(givenAccountValue);
            console.log("accountExpires", accountExpires);
  
            //* Convertir el valor a una fecha
            const accountExpiresDate = new Date((accountExpires/10000) - 11644473600000);
            console.log("accountExpiresDate", accountExpiresDate);
            
            //* Obtener la fecha actual
            const currentDate = new Date();
            
            if(accountExpires !== 0 && currentDate > accountExpiresDate){
              res.status(401).send("La cuenta ha expirado");
              return;
            }
          }

          //* Autenticar al usuario utilizando su contraseña
          authenticateUser(ldapClient, userDn, password, (authErr) => {
            if (authErr) {
              //* La autenticación ha fallado
              res.status(401).send("Credenciales Inválidas");
            } else {
              //* La autenticación ha sido exitosa
              res.status(200).send(userData);
            }
          });

        });

        //* Error en la búsqueda del usuario
        searchRes.on("error", (error) => {
          res.status(500).send("Error en la búsqueda del usuario");
        });

        //* No se encontró ningún usuario en el directorio activo
        searchRes.on("end", () => {
          if (!userFound) {
            res.status(404).send("Usuario no encontrado");
          }
        });
      }
    }
  );
});

//! //! Obtener todos los usuarios del directorio activo sin autenticación (GET)
app.get("/users", (req, res) => {
  const ldapClient = getLdapClient();
  const pageSize = 10; // Número de resultados por página
  let currentPage = 1; // Página actual

  // Función para realizar la búsqueda en LDAP con paginación
  const searchWithPagination = (page) => {
    const opts = {
      filter: "(objectClass=user)",
      scope: "sub",
      attributes: [
        "employeeID",
        "givenName",
        "sn",
        "mail",
        "userParameters",
        "employeeType",
      ],
      paged: {
        pageSize: pageSize,
        page: page
      }
    };

    ldapClient.search("OU=Usuarios,OU=INDER,DC=inder,DC=gov,DC=local", opts, (err, searchRes) => {
      if (err) {
        console.error("Error en la búsqueda de usuarios:", err);
        res.status(500).send("Error en la búsqueda de usuarios");
        return;
      }

      const usuarios = [];

      searchRes.on("searchEntry", (entry) => {
        const userData = {};

        entry.attributes.forEach((attribute) => {
          if (attribute.vals && attribute.vals.length > 0) {
            if (attribute.type === "givenName") {
              const [firstName, secondName] = attribute.vals[0].split(" ");
              userData["firstName"] = firstName;
              userData["secondName"] = secondName || "";
            } else if (attribute.type === "sn") {
              const [surname, secondSurname] = attribute.vals[0].split(" ");
              userData["surname"] = surname;
              userData["secondSurname"] = secondSurname || "";
            } else {
              userData[attribute.type] = attribute.vals[0];
            }
          }
        });

        usuarios.push(userData);
      });

      searchRes.on("error", (error) => {
        console.error("Error en la búsqueda de usuarios:", error);
        res.status(500).send("Error en la búsqueda de usuarios");
      });

      searchRes.on("end", () => {
        // Si hay más resultados, continuar con la siguiente página
        if (searchRes && searchRes.controls && searchRes.controls.length > 0) {
          const control = searchRes.controls.find(control => control.type === 'paged');
          if (control && control.value && control.value.size !== 0) {
            currentPage++;
            searchWithPagination(currentPage);
          }
        } else {
          // Si no hay más resultados, cerrar el cliente LDAP y enviar los usuarios como respuesta
          ldapClient.unbind();
          res.json(usuarios);
        }
      });
    });
  };

  // Iniciar la búsqueda con paginación
  searchWithPagination(currentPage);
});



app.listen(`${PORT}`, () => {
  console.log(`server en port ${PORT}`);
});
