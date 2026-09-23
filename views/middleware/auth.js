const { recordFailure, isLocked, clearAttempts } = require('./loginlimiter');

router.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const normalizedUsername = username.trim().toLowerCase();
  const key = `${req.ip}:${normalizedUsername}`;

  if (isLocked(key)) {
    return res.status(429).render('login', {
      error: 'Too many attempts. Try again in a few minutes.'
    });
  }

  const user = await findUserByUsername(normalizedUsername);
  const valid = user && await bcrypt.compare(password, user.passwordHash);

  if (!valid) {
    recordFailure(key);
    return res.render('login', { error: 'Invalid username or password' }); // generic on purpose
  }

  clearAttempts(key);

  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).render('login', { error: 'Something went wrong, try again.' });
    }
    req.session.userId = user.id;
    res.redirect('/admin');
  });
});