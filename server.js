const express = require('express');
const app = express();

var mysql = require('mysql');

// install first using npm install bcrypt
const bcrypt = require('bcrypt');

const conInfo = 
{
    host: process.env.IP,
    user: process.env.C9_USER,
    password: "",
    database: "SONGDB"
};

var session = require('express-session'); 
app.use(session({ secret: 'happy jungle', 
                  resave: false, 
                  saveUninitialized: false, 
                  cookie: { maxAge: 600000 }}))

app.all('/', whoIsLoggedIn);                  
app.all('/register', register);
app.all('/login', login);
app.all('/logout', logout);
app.all('/listUsers', listUsers);
app.all('/listSongs', listSongs);
app.all('/addSong', addSong);
app.all('/removeSong', removeSong);
app.all('/clearSongs', clearSongs);


app.listen(process.env.PORT,  process.env.IP, startHandler())

function startHandler()
{
  console.log('Server listening on port ' + process.env.PORT)
}

function listSongs(req, res)
{

  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      if(req.query.rating == undefined)
      {
        con.query("SELECT * FROM SONG ORDER BY SONG_NAME", function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
            writeResult(req, res, {'result' : result});
        });
      }
      else
      {
        con.query("SELECT * FROM SONG WHERE SONG_RATING = ? ORDER BY SONG_NAME", req.query.rating, function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
            writeResult(req, res, {'result' : result});
        });
      }
    }
  });
}

function addSong(req, res)
{
  if (req.session.user == undefined)
  {
    writeResult(req, res, {'error' : "Please login."});
    return;
  }
  
  if (req.query.song == undefined)
    writeResult(req, res, {'error' : "add requires you to enter a song"});
  if (req.query.rating == undefined)
    writeResult(req, res, {'error' : "add requires you to enter a rating"});
  
  else
  {
    var con = mysql.createConnection(conInfo);
    con.connect(function(err) 
    {
      if (err) 
        writeResult(req, res, {'error' : err});
      else
      {
        con.query('INSERT INTO SONG (SONG_NAME, USER_ID, SONG_RATING) VALUES (?, ?, ?)', [req.query.song, req.session.user.result.id, req.query.rating], function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
          {
            con.query("SELECT * FROM SONG WHERE USER_ID = ? ORDER BY SONG_NAME", [req.session.user.result.id], function (err, result, fields) 
            {
              if (err) 
                writeResult(req, res, {'error' : err});
              else
                writeResult(req, res, {'result' : result});
            });
          }
        });
      }
    });
  }
}

function removeSong(req, res)
{
  if (req.session.user == undefined)
  {
    writeResult(req, res, {'error' : "Please login."});
    return;
  }

  if (req.query.song == undefined)
    writeResult(req, res, {'error' : "add requires you to enter a song"});
  else
  {
    var con = mysql.createConnection(conInfo);
    con.connect(function(err) 
    {
      if (err) 
        writeResult(req, res, {'error' : err});
      else
      {
        con.query('DELETE FROM SONG WHERE SONG_NAME = ? AND USER_ID = ?', [req.query.song, req.session.user.result.id], function (err, result, fields) 
        {
          if (err) 
            writeResult(req, res, {'error' : err});
          else
          {
            con.query("SELECT * FROM SONG WHERE USER_ID = ? ORDER BY SONG_NAME", [req.session.user.result.id], function (err, result, fields) 
            {
              if (err) 
                writeResult(req, res, {'error' : err});
              else
                writeResult(req, res, {'result' : result});
            });
          }
        });
      }
    });
  }
}

function clearSongs(req, res)
{
  if (req.session.user == undefined)
  {
    writeResult(req, res, {'error' : "Please login."});
    return;
  }
  
  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      con.query('DELETE FROM SONG WHERE USER_ID = ?', [req.session.user.result.id], function (err, result, fields) 
      {
        if (err) 
          writeResult(req, res, {'error' : err});
        else
        {
          con.query("SELECT * FROM SONG WHERE USER_ID = ? ORDER BY SONG_NAME", [req.session.user.result.id], function (err, result, fields) 
          {
            if (err) 
              writeResult(req, res, {'error' : err});
            else
              writeResult(req, res, {'result' : result});
          });
        }
      });
    }
  });
}

function whoIsLoggedIn(req, res)
{
  if (req.session.user == undefined)
    writeResult(req, res, {'result' : 'Nobody is logged in.'});
  else
    writeResult(req, res, req.session.user);
}

function register(req, res)
{
  if (req.query.email == undefined || !validateEmail(req.query.email))
  {
    writeResult(req, res, {'error' : "Please specify a valid email"});
    return;
  }

  if (req.query.password == undefined || !validatePassword(req.query.password))
  {
    writeResult(req, res, {'error' : "Password must have a minimum of eight characters, at least one letter and one number"});
    return;
  }
  
  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      // bcrypt uses random salt is effective for fighting
      // rainbow tables, and the cost factor slows down the
      // algorithm which neutralizes brute force attacks ...
      let hash = bcrypt.hashSync(req.query.password, 12);
      req.session.logins = 1;
      con.query("INSERT INTO USER (USER_EMAIL, USER_PASS, USER_LOGINS) VALUES (?, ?, ?)", [req.query.email, hash, req.session.logins], function (err, result, fields) 
      {
        if (err) 
        {
          if (err.code == "ER_DUP_ENTRY")
            err = "User account already exists.";
          writeResult(req, res, {'error' : err});
        }
        else
        {
          con.query("SELECT * FROM USER WHERE USER_EMAIL = ?", [req.query.email], function (err, result, fields) 
          {
            if (err) 
              writeResult(req, res, {'error' : err});
            else
            {
              req.session.user = {'result' : {'id': result[0].USER_ID, 'email': result[0].USER_EMAIL, 'logins': result[0].USER_LOGINS}};
              writeResult(req, res, req.session.user);
            }
          });
        }
      });
    }
  });
  
}

function login(req, res)
{
  if (req.query.email == undefined)
  {
    writeResult(req, res, {'error' : "Email is required"});
    return;
  }

  if (req.query.password == undefined)
  {
    writeResult(req, res, {'error' : "Password is required"});
    return;
  }
  
  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      con.query("SELECT * FROM USER WHERE USER_EMAIL = ?", [req.query.email], function (err, result, fields) 
      {
        if (err) 
          writeResult(req, res, {'error' : err});
        else
        {
          if(result.length == 1 && bcrypt.compareSync(req.query.password, result[0].USER_PASS))
          {
            result[0].USER_LOGINS += 1;
            con.query("UPDATE USER SET USER_LOGINS = ? WHERE USER_ID = ?", [result[0].USER_LOGINS, result[0].USER_ID], function (err, result, fields) 
            {
              if(err)
                writeResult(req, res, {'error' : err});
              else
              {

              }
            
            });
            req.session.user = {'result' : {'id': result[0].USER_ID, 'email': result[0].USER_EMAIL, 'logins': result[0].USER_LOGINS}};
            writeResult(req, res, req.session.user);

          }
          else 
          {
            writeResult(req, res, {'error': "Invalid email/password"});
          }
        }
      });
    }
  });
}

function logout(req, res)
{
  req.session.user = undefined;
  writeResult(req, res, {'result' : 'Nobody is logged in.'});
}

function listUsers(req, res)
{
  var con = mysql.createConnection(conInfo);
  con.connect(function(err) 
  {
    if (err) 
      writeResult(req, res, {'error' : err});
    else
    {
      con.query("SELECT USER_ID, USER_EMAIL, USER_LOGINS FROM USER ORDER BY USER_LOGINS", function (err, result, fields) 
      {
        if (err) 
          writeResult(req, res, {'error' : err});
        else
          writeResult(req, res, {'result' : result});
      }); 
    }
  });
  
}

function writeResult(req, res, obj)
{
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.write(JSON.stringify(obj));
  res.end('');
}

function validateEmail(email) 
{
  if (email == undefined)
  {
    return false;
  }
  else
  {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
  }
}

function validatePassword(pass)
{
  if (pass == undefined)
  {
    return false;
  }
  else
  {
    var re = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return re.test(pass);
  }
}
