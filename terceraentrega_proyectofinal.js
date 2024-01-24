const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const GitHubStrategy = require('passport-github2').Strategy;

const userSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: { type: String, unique: true },
  age: Number,
  password: String,
  cart: { type: mongoose.Schema.Types.ObjectId, ref: 'Cart' },
  role: { type: String, default: 'user' },
});

const User = mongoose.model('User', userSchema);

passport.use(new LocalStrategy(
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email });

      if (!user || !(await bcrypt.compare(password, user.password))) {
        return done(null, false, { message: 'Usuario o contraseña incorrectos' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'tu_secreto',
};

passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
  try {
    const user = await User.findById(payload.id);

    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (error) {
    return done(error, false);
  }
}));


passport.use(new GitHubStrategy({
  clientID: 'tuClientID',
  clientSecret: 'tuClientSecret',
  callbackURL: 'http://tu-app-url/auth/github/callback'
},
async (accessToken, refreshToken, profile, done) => {
  try {
    
    let user = await User.findOne({ email: profile.emails[0].value });

    if (!user) {
      
      user = new User({
        email: profile.emails[0].value,
        first_name: profile.displayName || profile.username,
        
      });
      await user.save();
    }

    return done(null, user);
  } catch (error) {
    return done(error, false);
  }
}
));

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(session({
  secret: 'tu_secreto',
  resave: false,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());
app.use(express.json());

app.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Autenticación fallida' });
    }

    const token = jwt.sign({ id: user._id }, 'tu_secreto', { expiresIn: '1h' });

    return res.json({ token });
  })(req, res, next);
});

app.get('/api/sessions/current', passport.authenticate('jwt', { session: false }), (req, res) => {
  const userDto = {
    id: req.user._id,
    first_name: req.user.first_name,
    last_name: req.user.last_name,
    email: req.user.email,
    role: req.user.role,
  };

  res.json(userDto);
});

const repository = require('./repository');

const authorizeMiddleware = (req, res, next) => {
  const isAdmin = req.user && req.user.role === 'admin';

  if (isAdmin) {
    next();
  } else {
    res.status(403).json({ error: 'Acceso no autorizado' });
  }
};

const processPurchase = async (cart) => {
  
  return { success: true, failedProducts: [] };
};

const createTicket = async (cart, purchaserEmail) => {
  
  return ticket;
};

app.post('/api/carts/:cid/purchase', authorizeMiddleware, async (req, res) => {
  try {
    const cartId = req.params.cid;
    const cart = await repository.getCartById(cartId);

    
    const purchaseResult = await processPurchase(cart);

    if (purchaseResult.success) {
      
      const ticket = await createTicket(cart, req.user.email);

      
      await repository.clearCart(cartId);

      res.json({ message: 'Compra realizada con éxito', ticket });
    } else {
      res.json({ message: 'Algunos productos no pudieron ser comprados', failedProducts: purchaseResult.failedProducts });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

const port = 8080;
server.listen(port, () => {
  console.log(`Servidor escuchando en el puerto ${port}`);
});

mongoose.connect('mongodb+srv://<usuario>:<contraseña>@<cluster>/<base_de_datos>?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Error de conexión a MongoDB:'));
db.once('open', () => {
  console.log('Conexión exitosa a MongoDB');
});
