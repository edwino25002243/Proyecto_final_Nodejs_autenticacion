const { Router } = require('express');
const { register, login } = require('../controllers/auth.controller');
const { isAuth } = require('../middlewares/isAuth');

const router = Router();

router.post('/register', register);
router.post('/login', login);

router.get('/perfil', isAuth, (req, res) => {
  res.status(200).json({
    message: "¡Bienvenido a la ruta privada!",
    userData: req.user
  });
});

module.exports = router;