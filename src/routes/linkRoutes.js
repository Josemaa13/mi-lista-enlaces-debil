const express = require('express');
const router = express.Router();
const linkController = require('../controllers/linkController');
const requireAuth = require('../middlewares/authMiddleware');


router.get('/', requireAuth, linkController.getLinks);
router.post('/', requireAuth, linkController.createLink);
router.put('/:id', requireAuth, linkController.updateLink);
router.delete('/:id', requireAuth, linkController.deleteLink);

// Ruta SSRF
router.get('/preview', requireAuth, linkController.previewLink);

module.exports = router;