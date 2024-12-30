import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-local';
import bcrypt from 'bcrypt';

const app = express();
const port = 3000;
const saltRounds = 10;

dotenv.config();

// Set up session
app.use(
  session({
    secret: 'myBook',
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static('public'));

app.use(passport.initialize());
app.use(passport.session());

// Database connection
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

db.connect();

// Passport configuration
passport.use(
  new Strategy(async (username, password, cb) => {
    try {
      const result = await db.query('SELECT * FROM users WHERE username = $1', [
        username,
      ]);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const hashedPassword = user.password;

        bcrypt.compare(password, hashedPassword, (err, isMatch) => {
          if (err) {
            return cb(err);
          }
          if (isMatch) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (error) {
      return cb(error);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id); 
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

// Routes
app.get('/', (req, res) => {
  res.redirect('/signup');
});

app.get('/signup', (req, res) => {
  res.render('signup.ejs');
});

app.get('/login', (req, res) => {
  res.render('signup.ejs');
});

app.get('/register', (req, res) => {
  res.render('register.ejs');
});

app.get('/Home', async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        'SELECT * FROM books WHERE user_id = $1 ORDER BY id DESC',
        [req.user.id] // Assuming the books table has a `user_id` column
      );
      res.render('index.ejs', { books: result.rows });
    } catch (error) {
      console.error(error);
      res.send('Error fetching books.');
    }
  } else {
    res.redirect('/signup');
  }
});

app.get('/edit/:id', async (req, res) => {
  const currentId = req.params.id;
  const result = await db.query('SELECT * FROM books WHERE id = $1', [
    currentId,
  ]);
  res.render('editBook.ejs', { books: result.rows });
});

app.post('/add', async (req, res) => {
  const { title, author, notes, rate, date_read, isbn } = req.body;
  const userId = req.user.id;  // Get the logged-in user's ID

  await db.query(
    'INSERT INTO books (title, author, notes, rates, date_read, isbn, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [title, author, notes, rate, date_read, isbn, userId]  // Insert the user_id along with the book details
  );
  res.redirect('/Home');  // Redirect to the Home page
});


app.post('/delete/:id', async (req, res) => {
  const currentId = req.params.id;
  await db.query('DELETE FROM books WHERE id = $1', [currentId]);
  res.redirect('/Home');
});

app.post('/edit/:id', async (req, res) => {
  const curId = req.params.id;
  const { title, author, notes, rate, date_read, isbn } = req.body;
  await db.query(
    'UPDATE books SET title = $1, author = $2, notes = $3, rates = $4, date_read = $5, isbn = $6 WHERE id = $7',
    [title, author, notes, rate, date_read, isbn, curId]
  );
  res.redirect('/Home');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const checkResult = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    if (checkResult.rows.length > 0) {
      res.send('User already has an account!');
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error('Error hashing password!');
        } else {
          const result = await db.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
            [username, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.log(err);
            }
            res.redirect('/Home');
          });
        }
      });
    }
  } catch (error) {
    res.send('Registration failed.');
  }
});

app.post(
  '/signup',
  passport.authenticate('local', {
    successRedirect: '/Home',
    failureRedirect: '/signup',
  })
);

app.get('/adding', (req, res) => {
  res.render('addBook.ejs');
});

// Start the server
app.listen(port, () => {
  console.log(`Listening on port ${port} successfully!`);
});
