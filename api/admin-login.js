const crypto = require('crypto');

/* Signe un petit jeton (payload + expiration) avec une clé secrète
   connue uniquement du serveur. Le navigateur ne voit jamais le
   mot de passe ni la clé secrète : seulement ce jeton signé. */
function sign(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'Méthode non autorisée.' });
    return;
  }

  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  const TOKEN_SECRET = process.env.TOKEN_SECRET;

  if (!ADMIN_PASSWORD || !TOKEN_SECRET) {
    res.status(500).json({
      ok: false,
      error: "Le serveur n'est pas configuré. Ajoute ADMIN_PASSWORD et TOKEN_SECRET dans les variables d'environnement Vercel."
    });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const password = (body && body.password) || '';

  // Comparaison à temps constant : évite qu'on devine le mot de passe
  // caractère par caractère en mesurant le temps de réponse.
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!match) {
    res.status(401).json({ ok: false, error: 'Mot de passe incorrect.' });
    return;
  }

  const expires = Date.now() + 12 * 60 * 60 * 1000; // valable 12h
  const token = sign({ expires }, TOKEN_SECRET);

  res.status(200).json({ ok: true, token, expires });
};
