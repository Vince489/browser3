const express = require('express');
const router = express.Router();
const Site = require('../models/Site');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// GET /api/check/:domain - Check domain availability
router.get('/check/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const { tld } = req.query;

    if (!tld || !['vc', 'vmc', 'at', 'lit'].includes(tld)) {
      return res.status(400).json({ error: 'Invalid TLD' });
    }

    const existingSite = await Site.findOne({ domain, tld });
    const available = !existingSite;

    res.json({
      domain,
      tld,
      available,
      message: available ? 'Domain is available' : 'Domain is already registered'
    });
  } catch (error) {
    console.error('Domain check error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/register - Register new domain with key-based authentication
router.post('/register', async (req, res) => {
  try {
    const { domain, tld, target, title, description } = req.body;

    // Validate required fields
    if (!domain || !tld || !target) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate TLD
    if (!['vc', 'vmc', 'at', 'lit'].includes(tld)) {
      return res.status(400).json({ error: 'Invalid TLD' });
    }

    // Check if domain is available
    const existingSite = await Site.findOne({ domain, tld });
    if (existingSite) {
      return res.status(409).json({ error: 'Domain already registered' });
    }

    // Generate random secret key (v12-xxxx-xxxx format)
    const secretKey = `v12-${crypto.randomBytes(8).toString('hex')}`;

    // Hash the key for database storage
    const saltRounds = 10;
    const secretKeyHash = await bcrypt.hash(secretKey, saltRounds);

    // Create new site
    const newSite = new Site({
      domain,
      tld,
      target,
      secretKeyHash,
      title,
      description
    });

    await newSite.save();

    // Return the RAW key to user (shown only once)
    res.status(201).json({
      success: true,
      domain: `${domain}.${tld}`,
      secretKey: secretKey, // ⚠️ Only returned once!
      message: "SAVE THIS KEY! If you lose it, you cannot update your site."
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/update - Update existing domain (requires secret key)
router.put('/update', async (req, res) => {
  try {
    const { domain, tld, secretKey, target, title, description } = req.body;

    // Validate required fields
    if (!domain || !tld || !secretKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate TLD
    if (!['vc', 'vmc', 'at', 'lit'].includes(tld)) {
      return res.status(400).json({ error: 'Invalid TLD' });
    }

    // Find site
    const site = await Site.findOne({ domain, tld });
    if (!site) {
      return res.status(404).json({ error: "Domain not found" });
    }

    // Verify secret key
    const isValidKey = await bcrypt.compare(secretKey, site.secretKeyHash);
    if (!isValidKey) {
      return res.status(401).json({ error: "Invalid secret key" });
    }

    // Update site
    if (target) site.target = target;
    if (title !== undefined) site.title = title;
    if (description !== undefined) site.description = description;
    site.lastAccessed = new Date();

    await site.save();

    res.json({
      success: true,
      message: "Domain updated successfully",
      site: {
        domain: site.domain,
        tld: site.tld,
        target: site.target,
        title: site.title,
        description: site.description,
        lastAccessed: site.lastAccessed
      }
    });
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/delete - Delete domain (requires secret key)
router.delete('/delete', async (req, res) => {
  try {
    const { domain, tld, secretKey } = req.body;

    // Validate required fields
    if (!domain || !tld || !secretKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate TLD
    if (!['vc', 'vmc', 'at', 'lit'].includes(tld)) {
      return res.status(400).json({ error: 'Invalid TLD' });
    }

    // Find site
    const site = await Site.findOne({ domain, tld });
    if (!site) {
      return res.status(404).json({ error: "Domain not found" });
    }

    // Verify secret key
    const isValidKey = await bcrypt.compare(secretKey, site.secretKeyHash);
    if (!isValidKey) {
      return res.status(401).json({ error: "Invalid secret key" });
    }

    // Delete site
    await Site.deleteOne({ _id: site._id });

    res.json({
      success: true,
      message: "Domain deleted successfully"
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/lookup/:domain/:tld - DNS lookup
router.get('/lookup/:domain/:tld', async (req, res) => {
  try {
    const { domain, tld } = req.params;

    if (!['vc', 'vmc', 'at', 'lit'].includes(tld)) {
      return res.status(400).json({ error: 'Invalid TLD' });
    }

    const site = await Site.findOne({ domain, tld });
    if (!site) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    // Update last accessed
    site.lastAccessed = new Date();
    await site.save();

    // Convert GitHub URL to raw URL if needed
    let rawBase = site.target;
    if (site.target.startsWith('https://github.com/')) {
      rawBase = site.target
        .replace('github.com', 'raw.githubusercontent.com')
        .replace('/blob/', '/')
        .replace(/\/$/, '') + '/';
    }

    res.json({
      domain: site.domain,
      tld: site.tld,
      target: site.target,
      rawBase,
      title: site.title,
      description: site.description,
      verified: site.verified,
      createdAt: site.createdAt,
      lastAccessed: site.lastAccessed
    });
  } catch (error) {
    console.error('Lookup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/search - Search sites (basic implementation)
router.get('/search', async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Query parameter required' });
    }

    const results = await Site.find(
      { $text: { $search: q } },
      { score: { $meta: "textScore" } }
    )
    .sort({ score: { $meta: "textScore" } })
    .limit(20);

    res.json(results.map(site => ({
      domain: site.domain,
      tld: site.tld,
      title: site.title,
      description: site.description
    })));
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
