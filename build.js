#!/usr/bin/env node
// Builds dist/ from secrets.json (or bootstraps secrets.json on first run).
//
// Usage:
//   node build.js
//
// In CI, provide secrets via environment variables instead of committing secrets.json
// (see .github/workflows/rebuild.yml) -- this script will assemble secrets.json from
// env vars automatically when SITE_ADMIN_PASSCODE is set.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { base32Encode, base32Decode } = require('./lib/base32');
const { totpForCounter, counterForTime } = require('./lib/totp');
const {
  contextSalt,
  deriveKey,
  aesGcmEncrypt,
  randomKey,
  randomSalt,
} = require('./lib/crypto-node');

const ROOT = __dirname;
const SECRETS_PATH = path.join(ROOT, 'secrets.json');
const CREDENTIALS_PATH = path.join(ROOT, 'CREDENTIALS.txt');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DIST_DIR = path.join(ROOT, 'dist');

const DEFAULT_PAGES = [
  {
    id: 'survival',
    title: 'Survival',
    subpages: [
      {
        id: 'emergency-packs',
        title: 'Emergency Packs',
        content:
          "<p><em>Field manifests for three pack tiers. Tap items as you pack — progress is saved on this device.</em></p>\n<div class=\"pack-tier-nav\"><button class=\"pack-tier-btn active\" data-tier=\"ghb\">GHB · Get Home Bag</button><button class=\"pack-tier-btn\" data-tier=\"bob\">BOB · Bug Out Bag</button><button class=\"pack-tier-btn\" data-tier=\"srs\">SRS · Sustainment Rucksack</button></div>\n<div class=\"pack-tiers\"><div class=\"pack-tier-panel active\" data-tier=\"ghb\"><h3 class=\"pack-title\">GHB: Get Home Bag</h3><p class=\"pack-subhead\">The bare minimum to get through one night away from home — a get-home bag or grab-and-go kit, not a full 72-hour load.</p><div class=\"pack-specs\"><span><strong>Occupants:</strong> 1 adult</span><span><strong>Duration:</strong> ~12–24 hrs</span><span><strong>Target weight:</strong> ≤ 15 lb / 7 kg</span><span><strong>Review cycle:</strong> every 6 months</span></div><div class=\"pack-progress\"><span class=\"pack-progress-count\"><b class=\"pack-checked-count\">0</b> / <b class=\"pack-total-count\">0</b> packed</span><div class=\"pack-progress-track\"><div class=\"pack-progress-fill\"></div></div><button class=\"pack-reset\" type=\"button\">Reset checklist</button></div><div class=\"pack-notes\"><p><b>The bag itself:</b> a 20–30L daypack or sling bag. This should live within arm’s reach — car, desk, or entryway — not buried in a closet.</p><p><b>Purpose:</b> this tier gets you through one unplanned night or a walk home when the usual way isn’t an option. If you need more than a day, move up to the BOB.</p></div><div class=\"pack-legend\"><span class=\"pack-tag core\">Core</span> pack this first &nbsp;&nbsp; <span class=\"pack-tag rec\">Recommended</span> strong addition &nbsp;&nbsp; <span class=\"pack-tag opt\">Optional</span> nice to have</div><div class=\"pack-categories\"><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">01</span>Water</h4><p class=\"pack-cat-desc\">Enough to get through the night, not to resupply.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c0-i0\"><label for=\"ghb-c0-i0\"><span class=\"pack-item-name\">Water bottle</span><span class=\"pack-item-spec\">1 L min.</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c0-i1\"><label for=\"ghb-c0-i1\"><span class=\"pack-item-name\">Water purification tablets</span></label><span class=\"pack-tag core\">Core</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">02</span>Food</h4><p class=\"pack-cat-desc\">Calories, not cooking.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c1-i0\"><label for=\"ghb-c1-i0\"><span class=\"pack-item-name\">High-calorie bars or meal</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">03</span>Shelter & Warmth</h4><p class=\"pack-cat-desc\">One night's worth of protection from the elements.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c2-i0\"><label for=\"ghb-c2-i0\"><span class=\"pack-item-name\">Emergency space blanket</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c2-i1\"><label for=\"ghb-c2-i1\"><span class=\"pack-item-name\">Rain poncho</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c2-i2\"><label for=\"ghb-c2-i2\"><span class=\"pack-item-name\">Hand warmers</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">04</span>Clothing</h4><p class=\"pack-cat-desc\">One layer beyond what you're already wearing.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c3-i0\"><label for=\"ghb-c3-i0\"><span class=\"pack-item-name\">Extra socks</span><span class=\"pack-item-spec\">qty 1 pair</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c3-i1\"><label for=\"ghb-c3-i1\"><span class=\"pack-item-name\">Warm layer</span><span class=\"pack-item-spec\">fleece or jacket</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c3-i2\"><label for=\"ghb-c3-i2\"><span class=\"pack-item-name\">Gloves</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">05</span>First Aid</h4><p class=\"pack-cat-desc\">A mini kit for cuts, blisters, and headaches.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c4-i0\"><label for=\"ghb-c4-i0\"><span class=\"pack-item-name\">Mini trauma kit</span><span class=\"pack-item-spec\">bandages, tape, antiseptic</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c4-i1\"><label for=\"ghb-c4-i1\"><span class=\"pack-item-name\">Personal medication</span><span class=\"pack-item-spec\">1-day supply</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c4-i2\"><label for=\"ghb-c4-i2\"><span class=\"pack-item-name\">Pain relievers</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">06</span>Tools & Light</h4><p class=\"pack-cat-desc\">See, cut, and start a fire — nothing more.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c5-i0\"><label for=\"ghb-c5-i0\"><span class=\"pack-item-name\">Flashlight or headlamp</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c5-i1\"><label for=\"ghb-c5-i1\"><span class=\"pack-item-name\">Multitool or knife</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c5-i2\"><label for=\"ghb-c5-i2\"><span class=\"pack-item-name\">Lighter</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c5-i3\"><label for=\"ghb-c5-i3\"><span class=\"pack-item-name\">Duct tape</span><span class=\"pack-item-spec\">small roll</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">07</span>Nav & Comms</h4><p class=\"pack-cat-desc\">Stay findable, stay oriented.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c6-i0\"><label for=\"ghb-c6-i0\"><span class=\"pack-item-name\">Phone + charging cable</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c6-i1\"><label for=\"ghb-c6-i1\"><span class=\"pack-item-name\">Whistle</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c6-i2\"><label for=\"ghb-c6-i2\"><span class=\"pack-item-name\">Small paper map / home address card</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">08</span>Documents & Money</h4><p class=\"pack-cat-desc\">Enough to prove who you are and pay for something.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c7-i0\"><label for=\"ghb-c7-i0\"><span class=\"pack-item-name\">Copy of ID</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c7-i1\"><label for=\"ghb-c7-i1\"><span class=\"pack-item-name\">Cash in small bills</span></label><span class=\"pack-tag core\">Core</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">09</span>Personal</h4><p class=\"pack-cat-desc\">Small comforts and hygiene basics.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c8-i0\"><label for=\"ghb-c8-i0\"><span class=\"pack-item-name\">Hand sanitizer / wipes</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c8-i1\"><label for=\"ghb-c8-i1\"><span class=\"pack-item-name\">N95 / dust mask</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"ghb-c8-i2\"><label for=\"ghb-c8-i2\"><span class=\"pack-item-name\">Earplugs</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section></div><p class=\"pack-footnote\">Built for a 1-adult, single-night scenario. Need more than a day? Move up to the BOB.</p></div><div class=\"pack-tier-panel\" data-tier=\"bob\"><h3 class=\"pack-title\">BOB: Bug Out Bag</h3><p class=\"pack-subhead\">A complete packing list for a single adult, built around a 3-5 day self-sufficiency window in typical three-season conditions.</p><div class=\"pack-specs\"><span><strong>Occupants:</strong> 1 adult</span><span><strong>Duration:</strong> 3-5 days</span><span><strong>Target weight:</strong> ≤ 20% body weight</span><span><strong>Review cycle:</strong> every 6 months</span></div><div class=\"pack-progress\"><span class=\"pack-progress-count\"><b class=\"pack-checked-count\">0</b> / <b class=\"pack-total-count\">0</b> packed</span><div class=\"pack-progress-track\"><div class=\"pack-progress-fill\"></div></div><button class=\"pack-reset\" type=\"button\">Reset checklist</button></div><div class=\"pack-notes\"><p><b>The bag itself:</b> a 35–50L pack with a hip belt, so weight rides on your hips, not your shoulders. Compression straps and a rain cover matter more than pockets.</p><p><b>Weight budget:</b> aim to keep total pack weight under roughly 20% of your body weight (commonly 20–30 lb / 9–14 kg for an average adult). Weigh the packed bag, not the empty one, and cut before you add.</p><p><b>Maintenance:</b> set a recurring reminder to rotate food, water, and batteries and to check medications and documents for expiry — every 6 months lines up neatly with the twice-yearly clock-change weekends.</p></div><div class=\"pack-legend\"><span class=\"pack-tag core\">Core</span> pack this first &nbsp;&nbsp; <span class=\"pack-tag rec\">Recommended</span> strong addition &nbsp;&nbsp; <span class=\"pack-tag opt\">Optional</span> nice to have</div><div class=\"pack-categories\"><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">01</span>Water</h4><p class=\"pack-cat-desc\">Water is the first failure point. Carry some, and carry the means to make more.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c0-i0\"><label for=\"bob-c0-i0\"><span class=\"pack-item-name\">Bottled or bladder water</span><span class=\"pack-item-spec\">2–3 L min.</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c0-i1\"><label for=\"bob-c0-i1\"><span class=\"pack-item-name\">Portable water filter</span><span class=\"pack-item-spec\">e.g. Sawyer Squeeze</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c0-i2\"><label for=\"bob-c0-i2\"><span class=\"pack-item-name\">Water purification tablets</span><span class=\"pack-item-spec\">backup to filter</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c0-i3\"><label for=\"bob-c0-i3\"><span class=\"pack-item-name\">Collapsible water container</span><span class=\"pack-item-spec\">2–4 L</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c0-i4\"><label for=\"bob-c0-i4\"><span class=\"pack-item-name\">Electrolyte / rehydration packets</span><span class=\"pack-item-spec\">qty 6+</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c0-i5\"><label for=\"bob-c0-i5\"><span class=\"pack-item-name\">Water Filtration & Treatment Guide</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">02</span>Food</h4><p class=\"pack-cat-desc\">No-cook, calorie-dense, shelf-stable. Cooking gear is a bonus, not a requirement.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c1-i0\"><label for=\"bob-c1-i0\"><span class=\"pack-item-name\">Ready-to-eat food</span><span class=\"pack-item-spec\">~2,000 kcal/day × 3</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c1-i1\"><label for=\"bob-c1-i1\"><span class=\"pack-item-name\">Energy / protein bars</span><span class=\"pack-item-spec\">qty 6+</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c1-i2\"><label for=\"bob-c1-i2\"><span class=\"pack-item-name\">Manual can opener</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c1-i3\"><label for=\"bob-c1-i3\"><span class=\"pack-item-name\">Lightweight stove + fuel</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c1-i4\"><label for=\"bob-c1-i4\"><span class=\"pack-item-name\">Compact pot + long-handle spoon</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c1-i5\"><label for=\"bob-c1-i5\"><span class=\"pack-item-name\">Instant coffee or tea</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">03</span>Shelter</h4><p class=\"pack-cat-desc\">Exposure kills faster than hunger.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i0\"><label for=\"bob-c2-i0\"><span class=\"pack-item-name\">Compact tent, bivy, or tarp</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i1\"><label for=\"bob-c2-i1\"><span class=\"pack-item-name\">Emergency space blanket</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i2\"><label for=\"bob-c2-i2\"><span class=\"pack-item-name\">Sleeping bag or liner</span><span class=\"pack-item-spec\">3-season rated</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i3\"><label for=\"bob-c2-i3\"><span class=\"pack-item-name\">Line Kit</span><span class=\"pack-item-spec\">qty 2 minimum</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i4\"><label for=\"bob-c2-i4\"><span class=\"pack-item-name\">Compact sleeping pad</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i5\"><label for=\"bob-c2-i5\"><span class=\"pack-item-name\">Hand & foot warmers</span><span class=\"pack-item-spec\">qty 4</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c2-i6\"><label for=\"bob-c2-i6\"><span class=\"pack-item-name\">Rain poncho</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">04</span>Clothing</h4><p class=\"pack-cat-desc\">Wool and synthetic layering. Cotton KILLS.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i0\"><label for=\"bob-c3-i0\"><span class=\"pack-item-name\">Moisture-wicking base layer</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i1\"><label for=\"bob-c3-i1\"><span class=\"pack-item-name\">Wool socks</span><span class=\"pack-item-spec\">qty 2 pairs</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i2\"><label for=\"bob-c3-i2\"><span class=\"pack-item-name\">Underwear</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i3\"><label for=\"bob-c3-i3\"><span class=\"pack-item-name\">Broken-in boots</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i4\"><label for=\"bob-c3-i4\"><span class=\"pack-item-name\">Brimmed hat or boonie hat</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i5\"><label for=\"bob-c3-i5\"><span class=\"pack-item-name\">Gloves</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i6\"><label for=\"bob-c3-i6\"><span class=\"pack-item-name\">Durable belt</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i7\"><label for=\"bob-c3-i7\"><span class=\"pack-item-name\">Insulating mid-layer</span><span class=\"pack-item-spec\">fleece or wool</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i8\"><label for=\"bob-c3-i8\"><span class=\"pack-item-name\">Packable rain jacket</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c3-i9\"><label for=\"bob-c3-i9\"><span class=\"pack-item-name\">Bandana or buff</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">05</span>First Aid & Medical</h4><p class=\"pack-cat-desc\">A real trauma-capable kit, not a novelty tin. Add your own prescriptions last, and rotate them.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i0\"><label for=\"bob-c4-i0\"><span class=\"pack-item-name\">Assorted adhesive bandages</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i1\"><label for=\"bob-c4-i1\"><span class=\"pack-item-name\">Gauze pads & medical tape</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i2\"><label for=\"bob-c4-i2\"><span class=\"pack-item-name\">Elastic wrap / compression bandage</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i3\"><label for=\"bob-c4-i3\"><span class=\"pack-item-name\">Triangle bandages</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i4\"><label for=\"bob-c4-i4\"><span class=\"pack-item-name\">Antiseptic wipes & antibiotic ointment</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i5\"><label for=\"bob-c4-i5\"><span class=\"pack-item-name\">Blister treatment</span><span class=\"pack-item-spec\">moleskin</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i6\"><label for=\"bob-c4-i6\"><span class=\"pack-item-name\">Tweezers & small scissors</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i7\"><label for=\"bob-c4-i7\"><span class=\"pack-item-name\">Trauma shears</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i8\"><label for=\"bob-c4-i8\"><span class=\"pack-item-name\">Nitrile gloves</span><span class=\"pack-item-spec\">2 pairs</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i9\"><label for=\"bob-c4-i9\"><span class=\"pack-item-name\">Pain relievers / antihistamines</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i10\"><label for=\"bob-c4-i10\"><span class=\"pack-item-name\">Personal prescription meds</span><span class=\"pack-item-spec\">rotating supply</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i11\"><label for=\"bob-c4-i11\"><span class=\"pack-item-name\">Medical info card</span><span class=\"pack-item-spec\">allergies, conditions</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i12\"><label for=\"bob-c4-i12\"><span class=\"pack-item-name\">Anti-diarrheal & rehydration meds</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i13\"><label for=\"bob-c4-i13\"><span class=\"pack-item-name\">Tourniquet</span><span class=\"pack-item-spec\">qty 2 minimum</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i14\"><label for=\"bob-c4-i14\"><span class=\"pack-item-name\">Chest seals</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i15\"><label for=\"bob-c4-i15\"><span class=\"pack-item-name\">ThyroSafe</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i16\"><label for=\"bob-c4-i16\"><span class=\"pack-item-name\">SAM splint</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c4-i17\"><label for=\"bob-c4-i17\"><span class=\"pack-item-name\">N95 / dust masks</span><span class=\"pack-item-spec\">qty 3</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">06</span>Tools & Light</h4><p class=\"pack-cat-desc\">Cutting, fixing, seeing, and starting fires — the four jobs a bug-out kit must always cover.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i0\"><label for=\"bob-c5-i0\"><span class=\"pack-item-name\">Fixed-blade knife</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i1\"><label for=\"bob-c5-i1\"><span class=\"pack-item-name\">Multitool</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i2\"><label for=\"bob-c5-i2\"><span class=\"pack-item-name\">Headlamp + spare batteries</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i3\"><label for=\"bob-c5-i3\"><span class=\"pack-item-name\">Fire kit</span><span class=\"pack-item-spec\">lighter, ferro rod, tinder</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i4\"><label for=\"bob-c5-i4\"><span class=\"pack-item-name\">Duct tape</span><span class=\"pack-item-spec\">wrapped flat</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i5\"><label for=\"bob-c5-i5\"><span class=\"pack-item-name\">Repair kit</span><span class=\"pack-item-spec\">needle, thread, safety pins, zip ties</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i6\"><label for=\"bob-c5-i6\"><span class=\"pack-item-name\">Work gloves</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i7\"><label for=\"bob-c5-i7\"><span class=\"pack-item-name\">Backup flashlight</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i8\"><label for=\"bob-c5-i8\"><span class=\"pack-item-name\">Magnified optic</span><span class=\"pack-item-spec\">e.g. binoculars</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i9\"><label for=\"bob-c5-i9\"><span class=\"pack-item-name\">Entrenching tool</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i10\"><label for=\"bob-c5-i10\"><span class=\"pack-item-name\">Carabiner / S-biner</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i11\"><label for=\"bob-c5-i11\"><span class=\"pack-item-name\">Folding saw</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c5-i12\"><label for=\"bob-c5-i12\"><span class=\"pack-item-name\">Hand axe</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">07</span>Nav, Comms, & Tech.</h4><p class=\"pack-cat-desc\">Assume the network and your battery both fail. Paper and hand-crank power don't.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i0\"><label for=\"bob-c6-i0\"><span class=\"pack-item-name\">Paper map of your region</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i1\"><label for=\"bob-c6-i1\"><span class=\"pack-item-name\">Compass</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i2\"><label for=\"bob-c6-i2\"><span class=\"pack-item-name\">Power bank, charged</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i3\"><label for=\"bob-c6-i3\"><span class=\"pack-item-name\">Spare charging cable</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i4\"><label for=\"bob-c6-i4\"><span class=\"pack-item-name\">Waterproof notepad & pencil</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i5\"><label for=\"bob-c6-i5\"><span class=\"pack-item-name\">Signal whistle</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i6\"><label for=\"bob-c6-i6\"><span class=\"pack-item-name\">Handheld ham radio</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i7\"><label for=\"bob-c6-i7\"><span class=\"pack-item-name\">Hand-crank emergency radio</span><span class=\"pack-item-spec\">NOAA</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i8\"><label for=\"bob-c6-i8\"><span class=\"pack-item-name\">Signal mirror</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i9\"><label for=\"bob-c6-i9\"><span class=\"pack-item-name\">Small solar panel charger</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c6-i10\"><label for=\"bob-c6-i10\"><span class=\"pack-item-name\">Ranger beads</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">08</span>Documents & Money</h4><p class=\"pack-cat-desc\">Proof of who you are and access to funds when card networks or ID systems are down.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c7-i0\"><label for=\"bob-c7-i0\"><span class=\"pack-item-name\">Copies of ID / passport</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c7-i1\"><label for=\"bob-c7-i1\"><span class=\"pack-item-name\">Insurance & medical records</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c7-i2\"><label for=\"bob-c7-i2\"><span class=\"pack-item-name\">Emergency contact list</span><span class=\"pack-item-spec\">printed</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c7-i3\"><label for=\"bob-c7-i3\"><span class=\"pack-item-name\">Cash in small bills</span><span class=\"pack-item-spec\">$100–200</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c7-i4\"><label for=\"bob-c7-i4\"><span class=\"pack-item-name\">Waterproof document pouch</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c7-i5\"><label for=\"bob-c7-i5\"><span class=\"pack-item-name\">P.A.C.E Plan</span><span class=\"pack-item-spec\">printed</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">09</span>Hygiene & Sanitation</h4><p class=\"pack-cat-desc\">Small items that prevent big problems when normal facilities aren't available.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i0\"><label for=\"bob-c8-i0\"><span class=\"pack-item-name\">Compressed towel tablets</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i1\"><label for=\"bob-c8-i1\"><span class=\"pack-item-name\">Hand sanitizer</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i2\"><label for=\"bob-c8-i2\"><span class=\"pack-item-name\">Toothbrush & toothpaste</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i3\"><label for=\"bob-c8-i3\"><span class=\"pack-item-name\">Glasses / contacts & solution</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i4\"><label for=\"bob-c8-i4\"><span class=\"pack-item-name\">Feminine hygiene supplies</span><span class=\"pack-item-spec\">if needed</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i5\"><label for=\"bob-c8-i5\"><span class=\"pack-item-name\">Sunscreen (SPF)</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i6\"><label for=\"bob-c8-i6\"><span class=\"pack-item-name\">Small trowel</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i7\"><label for=\"bob-c8-i7\"><span class=\"pack-item-name\">Bar soap, travel-size</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c8-i8\"><label for=\"bob-c8-i8\"><span class=\"pack-item-name\">Wet wipes</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">10</span>Bag & Personal</h4><p class=\"pack-cat-desc\">The pack itself, organizational gear, and the small things that make a hard night easier.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i0\"><label for=\"bob-c9-i0\"><span class=\"pack-item-name\">35–50L pack</span><span class=\"pack-item-spec\">with hip belt</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i1\"><label for=\"bob-c9-i1\"><span class=\"pack-item-name\">Dry bags / zip-lock bags</span><span class=\"pack-item-spec\">assorted sizes</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i2\"><label for=\"bob-c9-i2\"><span class=\"pack-item-name\">Sunglasses</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i3\"><label for=\"bob-c9-i3\"><span class=\"pack-item-name\">Earplugs and Ear Pro</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i4\"><label for=\"bob-c9-i4\"><span class=\"pack-item-name\">Goggles</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i5\"><label for=\"bob-c9-i5\"><span class=\"pack-item-name\">Small comfort item</span><span class=\"pack-item-spec\">photo, book, etc.</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i6\"><label for=\"bob-c9-i6\"><span class=\"pack-item-name\">Pet supplies</span><span class=\"pack-item-spec\">if applicable</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i7\"><label for=\"bob-c9-i7\"><span class=\"pack-item-name\">Rain cover for pack</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"bob-c9-i8\"><label for=\"bob-c9-i8\"><span class=\"pack-item-name\">Field towel / microfiber</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section></div><div class=\"pack-climate\"><h4>Adjusting for climate</h4><div class=\"pack-climate-grid\"><div><h5>Cold / winter</h5><ul><li>Upgrade to a 0°F / -18°C rated sleeping bag</li><li>Add insulated boots and wool base layers</li><li>Double the hand/foot warmers</li><li>Watch batteries — cold drains them fast; keep spares warm, close to your body</li></ul></div><div><h5>Hot / arid</h5><ul><li>Increase water capacity to 4–6 L and add a wide-brim hat</li><li>Prioritize electrolytes over calories</li><li>Swap heavy layers for sun-protective, breathable fabric</li><li>Plan travel for early morning / evening to avoid peak heat</li></ul></div></div></div><p class=\"pack-footnote\">Built for a 1-adult / 3-5 day scenario — scale water, food, and medication quantities per additional person.</p></div><div class=\"pack-tier-panel\" data-tier=\"srs\"><h3 class=\"pack-title\">SRS: Sustainment Rucksack</h3><p class=\"pack-subhead\">The deep-loadout tier for a single adult — everything in the BOB plus the redundancy, EMP-protected cache, and hunting/defense support gear for an open-ended scenario.</p><div class=\"pack-specs\"><span><strong>Occupants:</strong> 1 adult</span><span><strong>Duration:</strong> extended / open-ended</span><span><strong>Target weight:</strong> ≤ 20% body weight</span><span><strong>Review cycle:</strong> every 6 months</span></div><div class=\"pack-progress\"><span class=\"pack-progress-count\"><b class=\"pack-checked-count\">0</b> / <b class=\"pack-total-count\">0</b> packed</span><div class=\"pack-progress-track\"><div class=\"pack-progress-fill\"></div></div><button class=\"pack-reset\" type=\"button\">Reset checklist</button></div><div class=\"pack-notes\"><p><b>The bag itself:</b> a 40–60L framed pack with a hip belt, so weight rides on your hips, not your shoulders. Compression straps and a rain cover matter more than pockets.</p><p><b>Weight budget:</b> aim to keep total pack weight under roughly 20% of your body weight (commonly 20–30 lb / 9–14 kg for an average adult). Weigh the packed bag, not the empty one, and cut before you add.</p><p><b>Maintenance:</b> set a recurring reminder to rotate food, water, and batteries and to check medications and documents for expiry — every 6 months lines up neatly with the twice-yearly clock-change weekends.</p></div><div class=\"pack-legend\"><span class=\"pack-tag core\">Core</span> pack this first &nbsp;&nbsp; <span class=\"pack-tag rec\">Recommended</span> strong addition &nbsp;&nbsp; <span class=\"pack-tag opt\">Optional</span> nice to have</div><div class=\"pack-categories\"><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">01</span>Water</h4><p class=\"pack-cat-desc\">Water is the first failure point. Carry some, and carry the means to make more.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c0-i0\"><label for=\"srs-c0-i0\"><span class=\"pack-item-name\">Bottled or bladder water</span><span class=\"pack-item-spec\">2–3 L min.</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c0-i1\"><label for=\"srs-c0-i1\"><span class=\"pack-item-name\">Portable water filter</span><span class=\"pack-item-spec\">e.g. Sawyer Squeeze</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c0-i2\"><label for=\"srs-c0-i2\"><span class=\"pack-item-name\">Water purification tablets</span><span class=\"pack-item-spec\">backup to filter</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c0-i3\"><label for=\"srs-c0-i3\"><span class=\"pack-item-name\">Collapsible water container</span><span class=\"pack-item-spec\">2–4 L</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c0-i4\"><label for=\"srs-c0-i4\"><span class=\"pack-item-name\">Electrolyte / rehydration packets</span><span class=\"pack-item-spec\">qty 6+</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c0-i5\"><label for=\"srs-c0-i5\"><span class=\"pack-item-name\">Water Filtration & Treatment Guide</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">02</span>Food</h4><p class=\"pack-cat-desc\">No-cook, calorie-dense, shelf-stable. Cooking gear is a bonus, not a requirement.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c1-i0\"><label for=\"srs-c1-i0\"><span class=\"pack-item-name\">Ready-to-eat food</span><span class=\"pack-item-spec\">~2,000 kcal/day × 3</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c1-i1\"><label for=\"srs-c1-i1\"><span class=\"pack-item-name\">Energy / protein bars</span><span class=\"pack-item-spec\">qty 6+</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c1-i2\"><label for=\"srs-c1-i2\"><span class=\"pack-item-name\">Manual can opener</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c1-i3\"><label for=\"srs-c1-i3\"><span class=\"pack-item-name\">Lightweight stove + fuel</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c1-i4\"><label for=\"srs-c1-i4\"><span class=\"pack-item-name\">Compact pot + long-handle spoon</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c1-i5\"><label for=\"srs-c1-i5\"><span class=\"pack-item-name\">Instant coffee or tea</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">03</span>Shelter</h4><p class=\"pack-cat-desc\">Exposure kills faster than hunger.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i0\"><label for=\"srs-c2-i0\"><span class=\"pack-item-name\">Compact tent, bivy, or tarp</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i1\"><label for=\"srs-c2-i1\"><span class=\"pack-item-name\">Emergency space blanket</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i2\"><label for=\"srs-c2-i2\"><span class=\"pack-item-name\">Sleeping bag or liner</span><span class=\"pack-item-spec\">3-season rated</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i3\"><label for=\"srs-c2-i3\"><span class=\"pack-item-name\">Line Kit</span><span class=\"pack-item-spec\">qty 2 minimum</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i4\"><label for=\"srs-c2-i4\"><span class=\"pack-item-name\">Compact sleeping pad</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i5\"><label for=\"srs-c2-i5\"><span class=\"pack-item-name\">Hand & foot warmers</span><span class=\"pack-item-spec\">qty 4</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c2-i6\"><label for=\"srs-c2-i6\"><span class=\"pack-item-name\">Rain poncho</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">04</span>Clothing</h4><p class=\"pack-cat-desc\">Wool and synthetic layering. Cotton KILLS.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i0\"><label for=\"srs-c3-i0\"><span class=\"pack-item-name\">Moisture-wicking base layer</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i1\"><label for=\"srs-c3-i1\"><span class=\"pack-item-name\">Wool socks</span><span class=\"pack-item-spec\">qty 2 pairs</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i2\"><label for=\"srs-c3-i2\"><span class=\"pack-item-name\">Underwear</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i3\"><label for=\"srs-c3-i3\"><span class=\"pack-item-name\">Broken-in boots</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i4\"><label for=\"srs-c3-i4\"><span class=\"pack-item-name\">Brimmed hat or boonie hat</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i5\"><label for=\"srs-c3-i5\"><span class=\"pack-item-name\">Gloves</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i6\"><label for=\"srs-c3-i6\"><span class=\"pack-item-name\">Durable belt</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i7\"><label for=\"srs-c3-i7\"><span class=\"pack-item-name\">Insulating mid-layer</span><span class=\"pack-item-spec\">fleece or wool</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i8\"><label for=\"srs-c3-i8\"><span class=\"pack-item-name\">Packable rain jacket</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c3-i9\"><label for=\"srs-c3-i9\"><span class=\"pack-item-name\">Bandana or buff</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">05</span>First Aid & Medical</h4><p class=\"pack-cat-desc\">A real trauma-capable kit, not a novelty tin. Add your own prescriptions last, and rotate them.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i0\"><label for=\"srs-c4-i0\"><span class=\"pack-item-name\">Assorted adhesive bandages</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i1\"><label for=\"srs-c4-i1\"><span class=\"pack-item-name\">Gauze pads & medical tape</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i2\"><label for=\"srs-c4-i2\"><span class=\"pack-item-name\">Elastic wrap / compression bandage</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i3\"><label for=\"srs-c4-i3\"><span class=\"pack-item-name\">Triangle bandages</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i4\"><label for=\"srs-c4-i4\"><span class=\"pack-item-name\">Antiseptic wipes & antibiotic ointment</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i5\"><label for=\"srs-c4-i5\"><span class=\"pack-item-name\">Blister treatment</span><span class=\"pack-item-spec\">moleskin</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i6\"><label for=\"srs-c4-i6\"><span class=\"pack-item-name\">Tweezers & small scissors</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i7\"><label for=\"srs-c4-i7\"><span class=\"pack-item-name\">Trauma shears</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i8\"><label for=\"srs-c4-i8\"><span class=\"pack-item-name\">Nitrile gloves</span><span class=\"pack-item-spec\">2 pairs</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i9\"><label for=\"srs-c4-i9\"><span class=\"pack-item-name\">Pain relievers / antihistamines</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i10\"><label for=\"srs-c4-i10\"><span class=\"pack-item-name\">Personal prescription meds</span><span class=\"pack-item-spec\">rotating supply</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i11\"><label for=\"srs-c4-i11\"><span class=\"pack-item-name\">Medical info card</span><span class=\"pack-item-spec\">allergies, conditions</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i12\"><label for=\"srs-c4-i12\"><span class=\"pack-item-name\">Anti-diarrheal & rehydration meds</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i13\"><label for=\"srs-c4-i13\"><span class=\"pack-item-name\">Tourniquet</span><span class=\"pack-item-spec\">qty 2 minimum</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i14\"><label for=\"srs-c4-i14\"><span class=\"pack-item-name\">Chest seals</span><span class=\"pack-item-spec\">qty 2</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i15\"><label for=\"srs-c4-i15\"><span class=\"pack-item-name\">ThyroSafe</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i16\"><label for=\"srs-c4-i16\"><span class=\"pack-item-name\">SAM splint</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c4-i17\"><label for=\"srs-c4-i17\"><span class=\"pack-item-name\">N95 / dust masks</span><span class=\"pack-item-spec\">qty 3</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">06</span>Tools & Light</h4><p class=\"pack-cat-desc\">Cutting, fixing, seeing, and starting fires — the four jobs a bug-out kit must always cover.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i0\"><label for=\"srs-c5-i0\"><span class=\"pack-item-name\">Fixed-blade knife</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i1\"><label for=\"srs-c5-i1\"><span class=\"pack-item-name\">Multitool</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i2\"><label for=\"srs-c5-i2\"><span class=\"pack-item-name\">Headlamp + spare batteries</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i3\"><label for=\"srs-c5-i3\"><span class=\"pack-item-name\">Fire kit</span><span class=\"pack-item-spec\">lighter, ferro rod, tinder</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i4\"><label for=\"srs-c5-i4\"><span class=\"pack-item-name\">Duct tape</span><span class=\"pack-item-spec\">wrapped flat</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i5\"><label for=\"srs-c5-i5\"><span class=\"pack-item-name\">Repair kit</span><span class=\"pack-item-spec\">needle, thread, safety pins, zip ties</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i6\"><label for=\"srs-c5-i6\"><span class=\"pack-item-name\">Work gloves</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i7\"><label for=\"srs-c5-i7\"><span class=\"pack-item-name\">Backup flashlight</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i8\"><label for=\"srs-c5-i8\"><span class=\"pack-item-name\">Magnified optic</span><span class=\"pack-item-spec\">e.g. binoculars</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i9\"><label for=\"srs-c5-i9\"><span class=\"pack-item-name\">Entrenching tool</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i10\"><label for=\"srs-c5-i10\"><span class=\"pack-item-name\">Carabiner / S-biner</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i11\"><label for=\"srs-c5-i11\"><span class=\"pack-item-name\">Folding saw</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c5-i12\"><label for=\"srs-c5-i12\"><span class=\"pack-item-name\">Hand axe</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">07</span>Nav, Comms, & Tech.</h4><p class=\"pack-cat-desc\">Assume the network and your battery both fail. Paper and hand-crank power don't.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i0\"><label for=\"srs-c6-i0\"><span class=\"pack-item-name\">Paper map of your region</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i1\"><label for=\"srs-c6-i1\"><span class=\"pack-item-name\">Compass and spare compass</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i2\"><label for=\"srs-c6-i2\"><span class=\"pack-item-name\">Protractor</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i3\"><label for=\"srs-c6-i3\"><span class=\"pack-item-name\">Power bank, charged</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i4\"><label for=\"srs-c6-i4\"><span class=\"pack-item-name\">Spare charging cable</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i5\"><label for=\"srs-c6-i5\"><span class=\"pack-item-name\">Handheld ham radio</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i6\"><label for=\"srs-c6-i6\"><span class=\"pack-item-name\">Waterproof notepad & pencil</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i7\"><label for=\"srs-c6-i7\"><span class=\"pack-item-name\">Signal whistle</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i8\"><label for=\"srs-c6-i8\"><span class=\"pack-item-name\">Hand-crank emergency radio</span><span class=\"pack-item-spec\">NOAA</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i9\"><label for=\"srs-c6-i9\"><span class=\"pack-item-name\">Signal mirror</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i10\"><label for=\"srs-c6-i10\"><span class=\"pack-item-name\">Small solar panel charger</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i11\"><label for=\"srs-c6-i11\"><span class=\"pack-item-name\">Ranger beads</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c6-i12\"><label for=\"srs-c6-i12\"><span class=\"pack-item-name\">Frequency / channel cheat sheet</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">08</span>Faraday Dry Bag</h4><p class=\"pack-cat-desc\">A waterproof dry bag with a Faraday bag inside it — a shielded, sealed cache of backup electronics and critical reference material, packed and forgotten until it’s needed.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c7-i0\"><label for=\"srs-c7-i0\"><span class=\"pack-item-name\">Dry bag</span><span class=\"pack-item-spec\">outer, waterproof</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c7-i1\"><label for=\"srs-c7-i1\"><span class=\"pack-item-name\">Faraday bag</span><span class=\"pack-item-spec\">inner, EMP/RF shielded</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c7-i2\"><label for=\"srs-c7-i2\"><span class=\"pack-item-name\">Spare phone</span><span class=\"pack-item-spec\">powered off</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c7-i3\"><label for=\"srs-c7-i3\"><span class=\"pack-item-name\">Charged battery bank</span><span class=\"pack-item-spec\">spare</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c7-i4\"><label for=\"srs-c7-i4\"><span class=\"pack-item-name\">Spare radio w/ charged battery</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c7-i5\"><label for=\"srs-c7-i5\"><span class=\"pack-item-name\">USB drive</span><span class=\"pack-item-spec\">maps, manuals, docs, locs, P.A.C.E.</span></label><span class=\"pack-tag core\">Core</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">09</span>Documents & Money</h4><p class=\"pack-cat-desc\">Proof of who you are and access to funds when card networks or ID systems are down.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c8-i0\"><label for=\"srs-c8-i0\"><span class=\"pack-item-name\">Copies of ID / passport</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c8-i1\"><label for=\"srs-c8-i1\"><span class=\"pack-item-name\">Insurance & medical records</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c8-i2\"><label for=\"srs-c8-i2\"><span class=\"pack-item-name\">Emergency contact list</span><span class=\"pack-item-spec\">printed</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c8-i3\"><label for=\"srs-c8-i3\"><span class=\"pack-item-name\">Cash in small bills</span><span class=\"pack-item-spec\">$100–200</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c8-i4\"><label for=\"srs-c8-i4\"><span class=\"pack-item-name\">Waterproof document pouch</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c8-i5\"><label for=\"srs-c8-i5\"><span class=\"pack-item-name\">P.A.C.E Plan</span><span class=\"pack-item-spec\">printed</span></label><span class=\"pack-tag rec\">Recommended</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">10</span>Hygiene & Sanitation</h4><p class=\"pack-cat-desc\">Small items that prevent big problems when normal facilities aren't available.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i0\"><label for=\"srs-c9-i0\"><span class=\"pack-item-name\">Compressed towel tablets</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i1\"><label for=\"srs-c9-i1\"><span class=\"pack-item-name\">Hand sanitizer</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i2\"><label for=\"srs-c9-i2\"><span class=\"pack-item-name\">Toothbrush & toothpaste</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i3\"><label for=\"srs-c9-i3\"><span class=\"pack-item-name\">Glasses / contacts & solution</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i4\"><label for=\"srs-c9-i4\"><span class=\"pack-item-name\">Feminine hygiene supplies</span><span class=\"pack-item-spec\">if needed</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i5\"><label for=\"srs-c9-i5\"><span class=\"pack-item-name\">Sunscreen (SPF)</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i6\"><label for=\"srs-c9-i6\"><span class=\"pack-item-name\">Small trowel</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i7\"><label for=\"srs-c9-i7\"><span class=\"pack-item-name\">Bar soap, travel-size</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c9-i8\"><label for=\"srs-c9-i8\"><span class=\"pack-item-name\">Wet wipes</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">11</span>Bag & Personal</h4><p class=\"pack-cat-desc\">The pack itself, organizational gear, and the small things that make a hard night easier.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i0\"><label for=\"srs-c10-i0\"><span class=\"pack-item-name\">40–60L framed pack</span><span class=\"pack-item-spec\">with hip belt</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i1\"><label for=\"srs-c10-i1\"><span class=\"pack-item-name\">Dry bags / zip-lock bags</span><span class=\"pack-item-spec\">assorted sizes</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i2\"><label for=\"srs-c10-i2\"><span class=\"pack-item-name\">Sunglasses</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i3\"><label for=\"srs-c10-i3\"><span class=\"pack-item-name\">Earplugs and Ear Pro</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i4\"><label for=\"srs-c10-i4\"><span class=\"pack-item-name\">Goggles</span></label><span class=\"pack-tag rec\">Recommended</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i5\"><label for=\"srs-c10-i5\"><span class=\"pack-item-name\">Small comfort item</span><span class=\"pack-item-spec\">photo, book, etc.</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i6\"><label for=\"srs-c10-i6\"><span class=\"pack-item-name\">Pet supplies</span><span class=\"pack-item-spec\">if applicable</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i7\"><label for=\"srs-c10-i7\"><span class=\"pack-item-name\">Rain cover for pack</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c10-i8\"><label for=\"srs-c10-i8\"><span class=\"pack-item-name\">Field towel / microfiber</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section><section class=\"pack-category\"><h4><span class=\"pack-cat-num\">12</span>Hunting & Defense</h4><p class=\"pack-cat-desc\">Assumes you’re already carrying a Primary and Secondary Weapon System — this is the support gear around them.</p><ul class=\"pack-items\"><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i0\"><label for=\"srs-c11-i0\"><span class=\"pack-item-name\">Extra loaded mags and spare ammunition</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i1\"><label for=\"srs-c11-i1\"><span class=\"pack-item-name\">Spare batteries for WML and optics</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i2\"><label for=\"srs-c11-i2\"><span class=\"pack-item-name\">Spare parts</span><span class=\"pack-item-spec\">firing pins, extractors, bolts, etc</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i3\"><label for=\"srs-c11-i3\"><span class=\"pack-item-name\">Cleaning kit</span></label><span class=\"pack-tag core\">Core</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i4\"><label for=\"srs-c11-i4\"><span class=\"pack-item-name\">.22 cal survival rifle / pistol</span><span class=\"pack-item-spec\">for small game</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i5\"><label for=\"srs-c11-i5\"><span class=\"pack-item-name\">NVG or Thermals</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i6\"><label for=\"srs-c11-i6\"><span class=\"pack-item-name\">Skinning knife</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i7\"><label for=\"srs-c11-i7\"><span class=\"pack-item-name\">Bone saw</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i8\"><label for=\"srs-c11-i8\"><span class=\"pack-item-name\">Snare wire / trapping kit</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i9\"><label for=\"srs-c11-i9\"><span class=\"pack-item-name\">Rangefinder</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i10\"><label for=\"srs-c11-i10\"><span class=\"pack-item-name\">Camo compact / face paint</span></label><span class=\"pack-tag opt\">Optional</span></li><li class=\"pack-item\"><input type=\"checkbox\" id=\"srs-c11-i11\"><label for=\"srs-c11-i11\"><span class=\"pack-item-name\">Game call</span></label><span class=\"pack-tag opt\">Optional</span></li></ul></section></div><div class=\"pack-climate\"><h4>Adjusting for climate</h4><div class=\"pack-climate-grid\"><div><h5>Cold / winter</h5><ul><li>Upgrade to a 0°F / -18°C rated sleeping bag</li><li>Add insulated boots and wool base layers</li><li>Double the hand/foot warmers</li><li>Watch batteries — cold drains them fast; keep spares warm, close to your body</li></ul></div><div><h5>Hot / arid</h5><ul><li>Increase water capacity to 4–6 L and add a wide-brim hat</li><li>Prioritize electrolytes over calories</li><li>Swap heavy layers for sun-protective, breathable fabric</li><li>Plan travel for early morning / evening to avoid peak heat</li></ul></div></div></div><p class=\"pack-footnote\">Built for a 1-adult, open-ended scenario — scale water, food, and medication quantities per additional person.</p></div></div>",
      },
      {
        id: 'terrain-land-nav',
        title: 'Terrain & Land Nav',
        content:
          '<ul>\n' +
          '  <li>Map and compass basics, declination</li>\n' +
          '  <li>Reading topographic features</li>\n' +
          '  <li>Dead reckoning and triangulation</li>\n' +
          '  <li>GPS backup and offline maps</li>\n' +
          '</ul>',
      },
      {
        id: 'urban-survival',
        title: 'Urban Survival',
        content:
          '<ul>\n' +
          '  <li>Sheltering in place vs. evacuation</li>\n' +
          '  <li>Urban water and food sourcing</li>\n' +
          '  <li>Situational awareness</li>\n' +
          '  <li>Utility failures: power, water, gas</li>\n' +
          '</ul>',
      },
      {
        id: 'wilderness-survival',
        title: 'Wilderness Survival',
        content:
          '<ul>\n' +
          '  <li>Priorities of survival: shelter, fire, water, food</li>\n' +
          '  <li>Signaling for rescue</li>\n' +
          '  <li>Staying put vs. self-rescue decision points</li>\n' +
          '</ul>',
      },
      {
        id: 'water-procurement-treatment',
        title: 'Water Procurement & Treatment',
        content:
          '<ul>\n' +
          '  <li>Sourcing: streams, dew collection, transpiration bags</li>\n' +
          '  <li>Filtration methods</li>\n' +
          '  <li>Boiling and chemical treatment</li>\n' +
          '  <li>Storage and rationing</li>\n' +
          '</ul>',
      },
      {
        id: 'firecraft',
        title: 'Firecraft',
        content:
          '<ul>\n' +
          '  <li>Fire-starting methods: friction, ferro rod, matches</li>\n' +
          '  <li>Tinder, kindling, fuel wood selection</li>\n' +
          '  <li>Fire lays for cooking, warmth, signaling</li>\n' +
          '  <li>Fire safety and Leave No Trace</li>\n' +
          '</ul>',
      },
      {
        id: 'wilderness-first-aid',
        title: 'Wilderness First-Aid',
        content:
          '<ul>\n' +
          '  <li>Trauma basics: bleeding control, splinting</li>\n' +
          '  <li>Environmental injuries: heat, cold, dehydration</li>\n' +
          '  <li>Improvised medical kit</li>\n' +
          '  <li>Evacuation criteria</li>\n' +
          '</ul>',
      },
      {
        id: 'foraging-botany',
        title: 'Foraging & Botany',
        content:
          '<ul>\n' +
          '  <li>Universal edibility test</li>\n' +
          '  <li>Common edible/poisonous look-alikes</li>\n' +
          '  <li>Seasonal foraging calendar</li>\n' +
          '  <li>Regional plant ID resources</li>\n' +
          '</ul>',
      },
      {
        id: 'knot-rope-work',
        title: 'Knot & Rope Work',
        content:
          '<ul>\n' +
          '  <li>Core knots: bowline, clove hitch, taut-line hitch</li>\n' +
          '  <li>Lashings for shelter building</li>\n' +
          '  <li>Rope care and selection</li>\n' +
          '</ul>',
      },
      {
        id: 'hunting-trapping-fishing',
        title: 'Hunting, Trapping & Fishing',
        content:
          '<ul>\n' +
          '  <li>Passive trap and snare basics</li>\n' +
          '  <li>Improvised fishing rigs</li>\n' +
          '  <li>Legal/regulatory considerations</li>\n' +
          '  <li>Field dressing basics</li>\n' +
          '</ul>',
      },
      {
        id: 'shelter-site-selection',
        title: 'Shelter & Site Selection',
        content:
          '<ul>\n' +
          '  <li>Site selection criteria: drainage, wind, hazards</li>\n' +
          '  <li>Debris hut, lean-to, tarp configurations</li>\n' +
          '  <li>Insulation from the ground</li>\n' +
          '</ul>',
      },
      {
        id: 'bushcraft-bivouacking',
        title: 'Bushcraft & Bivouacking',
        content:
          '<ul>\n' +
          '  <li>Tool use and maintenance: knife, axe, saw</li>\n' +
          '  <li>Bivy setup for short overnight stops</li>\n' +
          '  <li>Camp craft essentials</li>\n' +
          '</ul>',
      },
      {
        id: 'mountaineering',
        title: 'Mountaineering',
        content:
          '<ul>\n' +
          '  <li>Route planning and weather windows</li>\n' +
          '  <li>Basic rope systems and belaying</li>\n' +
          '  <li>Altitude acclimatization</li>\n' +
          '  <li>Rockfall and avalanche awareness</li>\n' +
          '</ul>',
      },
      {
        id: 'winter-alpine-survival',
        title: 'Winter/Alpine Survival',
        content:
          '<ul>\n' +
          '  <li>Cold injury prevention: frostbite, hypothermia</li>\n' +
          '  <li>Snow shelter construction</li>\n' +
          '  <li>Layering systems</li>\n' +
          '  <li>Avalanche basics</li>\n' +
          '</ul>',
      },
      {
        id: 'arid-desert-survival',
        title: 'Arid/Desert Survival',
        content:
          '<ul>\n' +
          '  <li>Water rationing and heat management</li>\n' +
          '  <li>Shade and shelter in open terrain</li>\n' +
          '  <li>Travel timing: night movement</li>\n' +
          '  <li>Signaling in open terrain</li>\n' +
          '</ul>',
      },
    ],
  },
  {
    id: 'technical',
    title: 'Technical',
    subpages: [
      {
        id: 'radio-comms',
        title: 'Radio Comms',
        content:
          '<p><em>Placeholder page. Replace this with your own reference material.</em></p>\n' +
          '<ul>\n' +
          '  <li>Frequency plan and channel assignments</li>\n' +
          '  <li>License requirements: HAM, GMRS, etc.</li>\n' +
          '  <li>Base/mobile/handheld radio inventory</li>\n' +
          '  <li>Antenna setups and range considerations</li>\n' +
          '</ul>',
      },
      {
        id: 'sat-comms',
        title: 'Sat Comms',
        content:
          '<ul>\n' +
          '  <li>Satellite phone/messenger inventory (Garmin inReach, Iridium, etc.)</li>\n' +
          '  <li>Coverage areas and subscription status</li>\n' +
          '  <li>Emergency SOS procedures</li>\n' +
          '  <li>Backup power for sat devices</li>\n' +
          '</ul>',
      },
      {
        id: 'sigint',
        title: 'SIG.INT',
        content:
          '<ul>\n' +
          '  <li>SDR (software-defined radio) setup and scanning</li>\n' +
          '  <li>Frequency monitoring equipment</li>\n' +
          '  <li>Signal logging and analysis tools</li>\n' +
          '</ul>',
      },
      {
        id: 'cybersec',
        title: 'CyberSec',
        content:
          '<ul>\n' +
          '  <li>Device hardening checklist</li>\n' +
          '  <li>Password/passphrase management</li>\n' +
          '  <li>VPN and network security</li>\n' +
          '  <li>Backup and recovery procedures</li>\n' +
          '</ul>',
      },
      {
        id: 'diy-cell-network',
        title: 'DIY Cell Tower/Network',
        content:
          '<ul>\n' +
          '  <li>Mesh network options (goTenna, Meshtastic, etc.)</li>\n' +
          '  <li>Local/offline network setup</li>\n' +
          '  <li>Legal considerations</li>\n' +
          '  <li>Range and node placement</li>\n' +
          '</ul>',
      },
      {
        id: 'encryption',
        title: 'Encryption',
        content:
          '<ul>\n' +
          '  <li>File and disk encryption tools</li>\n' +
          '  <li>Secure messaging apps</li>\n' +
          '  <li>Key management and backup</li>\n' +
          '  <li>PGP/GPG basics</li>\n' +
          '</ul>',
      },
      {
        id: 'flock-tracker',
        title: 'Flock Tracker',
        content:
          '<ul>\n' +
          '  <li>Known ALPR/Flock camera locations</li>\n' +
          '  <li>Route planning and situational awareness</li>\n' +
          '  <li>Community-maintained tracking resources</li>\n' +
          '</ul>',
      },
      {
        id: 'flipperzero',
        title: 'FlipperZero',
        content:
          '<ul>\n' +
          '  <li>Device capabilities overview</li>\n' +
          '  <li>Firmware and app management</li>\n' +
          '  <li>Use cases: RFID/NFC, sub-GHz, infrared</li>\n' +
          '  <li>Legal/ethical considerations</li>\n' +
          '</ul>',
      },
      {
        id: 'design-files-3d',
        title: '3D-Print Design Files',
        content:
          '<ul>\n' +
          '  <li>File library organization</li>\n' +
          '  <li>Printer settings and materials</li>\n' +
          '  <li>Priority print list</li>\n' +
          '  <li>Repair/replacement parts</li>\n' +
          '</ul>',
      },
      {
        id: 'cyberdeck',
        title: 'CyberDeck',
        content:
          '<ul>\n' +
          '  <li>Build specs and components</li>\n' +
          '  <li>Software loadout</li>\n' +
          '  <li>Power management and battery life</li>\n' +
          '  <li>Use cases in the field</li>\n' +
          '</ul>',
      },
    ],
  },
  {
    id: 'tactical',
    title: 'Tactical',
    subpages: [
      {
        id: 'team-roster',
        title: 'Team Roster',
        content:
          '<p><em>Placeholder page. Replace this with your own reference material.</em></p>\n' +
          '<ul>\n' +
          '  <li>Roster: names, roles, contact info</li>\n' +
          '  <li>Chain of command</li>\n' +
          '  <li>Emergency contacts</li>\n' +
          '</ul>',
      },
      {
        id: 'squads',
        title: 'Squads',
        content:
          '<ul>\n' +
          '  <li>Squad composition and organization</li>\n' +
          '  <li>Squad assignments and rally roles</li>\n' +
          '  <li>Cross-training and backup assignments</li>\n' +
          '</ul>',
      },
      {
        id: 'armory',
        title: 'Armory',
        content:
          '<ul>\n' +
          '  <li>Weapons inventory and assignment</li>\n' +
          '  <li>Ammunition stock and rotation</li>\n' +
          '  <li>Maintenance schedule and cleaning log</li>\n' +
          '  <li>Storage and security</li>\n' +
          '</ul>',
      },
      {
        id: 'missions',
        title: 'Missions',
        content:
          '<ul>\n' +
          '  <li>Current mission briefs and objectives</li>\n' +
          '  <li>Timelines and rally points</li>\n' +
          '  <li>After-action review notes</li>\n' +
          '</ul>',
      },
      {
        id: 'sit-reps',
        title: 'SIT.REPS',
        content:
          '<ul>\n' +
          '  <li>Situation report format</li>\n' +
          '  <li>Reporting schedule and check-in windows</li>\n' +
          '  <li>Escalation criteria</li>\n' +
          '</ul>',
      },
      {
        id: 'assets',
        title: 'Assets',
        content:
          '<ul>\n' +
          '  <li>Vehicles and fuel status</li>\n' +
          '  <li>Equipment inventory</li>\n' +
          '  <li>Property and resource tracking</li>\n' +
          '</ul>',
      },
      {
        id: 'pace',
        title: 'P.A.C.E.',
        content:
          '<p><em>Primary, Alternate, Contingency, Emergency — layered fallback plans.</em></p>\n' +
          '<ul>\n' +
          '  <li>Primary: communication and movement plan</li>\n' +
          '  <li>Alternate: backup channels and routes</li>\n' +
          '  <li>Contingency: degraded/limited options</li>\n' +
          '  <li>Emergency: last-resort plan</li>\n' +
          '</ul>',
      },
      {
        id: 'opsec',
        title: 'Op.Sec',
        content:
          '<ul>\n' +
          '  <li>Information compartmentalization</li>\n' +
          '  <li>Comms discipline and code words</li>\n' +
          '  <li>Physical and digital footprint reduction</li>\n' +
          '</ul>',
      },
    ],
  },
];

function log(...args) {
  console.log('[build]', ...args);
}

function randomPasscode(bytes = 9) {
  // URL-safe, easy to read aloud-ish, ~12 base64url chars from 9 random bytes.
  return crypto.randomBytes(bytes).toString('base64url');
}

function loadOrBootstrapSecrets() {
  // CI path: assemble secrets.json from environment variables if present.
  if (process.env.SITE_USERS_JSON) {
    log('Assembling secrets from environment variables (CI mode).');
    return {
      users: JSON.parse(process.env.SITE_USERS_JSON),
      totp: {
        base32Secret: process.env.SITE_TOTP_SECRET_BASE32,
        periodSeconds: Number(process.env.SITE_TOTP_PERIOD_SECONDS || 1800),
        digits: Number(process.env.SITE_TOTP_DIGITS || 6),
        accessAllPages: true,
      },
      pages: DEFAULT_PAGES,
    };
  }

  if (fs.existsSync(SECRETS_PATH)) {
    log('Loading existing secrets.json');
    return JSON.parse(fs.readFileSync(SECRETS_PATH, 'utf8'));
  }

  log('No secrets.json found -- bootstrapping new random credentials.');
  const totpSecretBytes = crypto.randomBytes(20); // 160-bit, standard TOTP secret size
  const secrets = {
    users: [
      { username: 'admin', passcode: randomPasscode(12), allPages: true },
      ...DEFAULT_PAGES.map((p) => ({
        username: p.id,
        passcode: randomPasscode(9),
        pages: [p.id],
      })),
    ],
    totp: {
      base32Secret: base32Encode(totpSecretBytes),
      periodSeconds: 1800, // 30 minutes
      digits: 6,
      accessAllPages: true,
    },
    pages: DEFAULT_PAGES,
  };

  fs.writeFileSync(SECRETS_PATH, JSON.stringify(secrets, null, 2));
  log('Wrote secrets.json (keep this file private -- it is gitignored).');
  writeCredentialsFile(secrets);
  return secrets;
}

function writeCredentialsFile(secrets) {
  const otpauthUri =
    'otpauth://totp/SurvivalOps:rotating-access?secret=' +
    secrets.totp.base32Secret +
    '&issuer=SurvivalOps&period=' +
    secrets.totp.periodSeconds +
    '&digits=' +
    secrets.totp.digits;

  const lines = [];
  lines.push('SURVIVAL/OPS SITE -- ACCESS CREDENTIALS');
  lines.push('Generated: ' + new Date().toISOString());
  lines.push('');
  lines.push('KEEP THIS FILE PRIVATE. Distribute individual logins to team members');
  lines.push('over a secure channel (not email/SMS in plaintext if you can avoid it).');
  lines.push('');
  lines.push('USER LOGINS (username + passcode, each with its own page access):');
  for (const u of secrets.users) {
    const access = u.allPages ? 'ALL PAGES' : (u.pages || []).join(', ') || '(none)';
    lines.push('  ' + u.username + ' / ' + u.passcode + '  -- access: ' + access);
  }
  lines.push('');
  lines.push('To change what a user can see, edit their "pages" array (or "allPages": true');
  lines.push('for full access) in secrets.json, under "users", then rebuild.');
  lines.push('');
  lines.push('ROTATING ACCESS CODE (TOTP, changes every ' + secrets.totp.periodSeconds / 60 + ' minutes, unlocks all pages, no username needed):');
  lines.push('  Add this to an authenticator app (Google Authenticator, Authy, 1Password, etc.)');
  lines.push('  Either scan totp-qr.png (in this same folder after build) or enter manually:');
  lines.push('    Secret (base32): ' + secrets.totp.base32Secret);
  lines.push('    Type: Time-based, Digits: ' + secrets.totp.digits + ', Period: ' + secrets.totp.periodSeconds + 's');
  lines.push('  otpauth URI: ' + otpauthUri);
  lines.push('');
  lines.push('Remember: the rotating code only stays in sync if the site is rebuilt');
  lines.push('periodically (see .github/workflows/rebuild.yml). A stale build will reject');
  lines.push('otherwise-correct rotating codes once enough time has passed.');

  fs.writeFileSync(CREDENTIALS_PATH, lines.join('\n') + '\n');
  log('Wrote CREDENTIALS.txt (private, gitignored) with all generated codes.');
}

function encryptSubpageContent(subKey, subpage) {
  const { iv, ct } = aesGcmEncrypt(subKey, Buffer.from(subpage.content, 'utf8'));
  return { iv, ct };
}

function wrapKeyForPasscode(subKey, passcode, baseSalt, context) {
  const salt = contextSalt(baseSalt, context);
  const kek = deriveKey(passcode, salt);
  const { iv, ct } = aesGcmEncrypt(kek, subKey);
  return { context, iv, ct };
}

// Users authenticate with a username + passcode pair. Both must be exactly
// right: the derivation key is "username:passcode", not just the passcode,
// so knowing one user's passcode (or seeing another user's username in a
// sub-page's wrapped-entry list) doesn't help unlock a different user's login.
function wrapKeyForUser(subKey, user, baseSalt) {
  return wrapKeyForPasscode(subKey, user.username + ':' + user.passcode, baseSalt, 'user:' + user.username);
}

// Access is granted per sub-page. A user's "pages" entries can be either a
// whole page id ("survival", granting every sub-page under it) or a single
// sub-page scoped as "pageId:subpageId" (e.g. "survival:emergency-packs",
// granting only that one tab).
function userGrantsSubpage(user, pageId, subpageId) {
  if (user.allPages === true) return true;
  if (!Array.isArray(user.pages)) return false;
  return user.pages.includes(pageId) || user.pages.includes(pageId + ':' + subpageId);
}

function buildTotpWrappedEntries(pageKey, baseSalt, totpConfig) {
  if (!totpConfig || !totpConfig.base32Secret) return [];
  const secretBuf = base32Decode(totpConfig.base32Secret);
  const nowSec = Math.floor(Date.now() / 1000);
  const period = totpConfig.periodSeconds || 1800;
  const digits = totpConfig.digits || 6;
  const currentCounter = counterForTime(nowSec, period);

  const entries = [];
  // Accept previous, current, and next window to tolerate clock skew / rebuild timing.
  for (const offset of [-1, 0, 1]) {
    const counter = currentCounter + offset;
    const code = totpForCounter(secretBuf, counter, digits);
    const salt = contextSalt(baseSalt, 'totp:' + counter);
    const kek = deriveKey(code, salt);
    const { iv, ct } = aesGcmEncrypt(kek, pageKey);
    entries.push({ context: 'totp:' + counter, iv, ct });
  }
  return entries;
}

// Builds the Admin page's content fresh from the current users list on every
// build, so it's never stale relative to secrets.json. Admin-level (allPages)
// users are left out of the listing -- this shows the logins an admin
// manages, not other admins' own credentials.
function buildAdminPageContent(secrets) {
  const rows = (secrets.users || [])
    .filter((u) => !u.allPages)
    .map((u) => {
      const access = (u.pages || []).join(', ') || '(none)';
      return '  <li><strong>' + u.username + '</strong> / ' + u.passcode + ' &mdash; access: ' + access + '</li>';
    })
    .join('\n');

  return (
    '<p><em>Visible only to admin-level logins. Does not list other admin passcodes.</em></p>\n' +
    '<ul>\n' + (rows || '  <li>No non-admin users configured.</li>') + '\n</ul>'
  );
}

function main() {
  const secrets = loadOrBootstrapSecrets();

  // Synthesized fresh from secrets.users on every build -- not something you
  // edit directly in secrets.json's pages array. Access follows the normal
  // userGrantsSubpage() rule below, so only allPages users see it by default.
  const adminPage = {
    id: 'admin',
    title: 'Admin',
    subpages: [{ id: 'users', title: 'Users', content: buildAdminPageContent(secrets) }],
  };
  secrets.pages = [...secrets.pages, adminPage];

  if (fs.existsSync(DIST_DIR)) {
    fs.rmSync(DIST_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(DIST_DIR, { recursive: true });
  fs.mkdirSync(path.join(DIST_DIR, 'pages'), { recursive: true });

  // Copy static frontend assets as-is.
  for (const file of fs.readdirSync(PUBLIC_DIR)) {
    fs.copyFileSync(path.join(PUBLIC_DIR, file), path.join(DIST_DIR, file));
  }

  const manifest = [];

  for (const page of secrets.pages) {
    const totpGrantsThisPage =
      secrets.totp &&
      secrets.totp.base32Secret &&
      (secrets.totp.accessAllPages !== false) &&
      (!secrets.totp.pages || secrets.totp.pages.includes(page.id));

    // Each sub-page gets its own random key, salt, and wrapped-entry list, so
    // access can be scoped down to a single tab rather than the whole page --
    // only sub-page id/title stay public (same idea as page id/title in
    // manifest.json), letting a locked-out viewer see tab labels without
    // being able to decrypt what's under them.
    const subpagesOut = (page.subpages || []).map((subpage) => {
      const baseSalt = randomSalt(16);
      const subKey = randomKey();
      const content = encryptSubpageContent(subKey, subpage);

      const wrapped = [];
      for (const user of secrets.users || []) {
        if (userGrantsSubpage(user, page.id, subpage.id)) {
          wrapped.push(wrapKeyForUser(subKey, user, baseSalt));
        }
      }
      if (totpGrantsThisPage) {
        wrapped.push(...buildTotpWrappedEntries(subKey, baseSalt, secrets.totp));
      }

      return {
        id: subpage.id,
        title: subpage.title,
        salt: baseSalt.toString('base64'),
        content,
        wrapped,
      };
    });

    fs.writeFileSync(
      path.join(DIST_DIR, 'pages', page.id + '.json'),
      JSON.stringify({ id: page.id, title: page.title, subpages: subpagesOut })
    );

    manifest.push({ id: page.id, title: page.title });
  }

  fs.writeFileSync(path.join(DIST_DIR, 'pages', 'manifest.json'), JSON.stringify(manifest));

  log('Built ' + manifest.length + ' page(s) into dist/.');

  // Generate a QR code for the TOTP secret if the qrcode package is available.
  if (secrets.totp && secrets.totp.base32Secret) {
    try {
      const QRCode = require('qrcode');
      const otpauthUri =
        'otpauth://totp/SurvivalOps:rotating-access?secret=' +
        secrets.totp.base32Secret +
        '&issuer=SurvivalOps&period=' +
        secrets.totp.periodSeconds +
        '&digits=' +
        secrets.totp.digits;
      QRCode.toFile(path.join(ROOT, 'totp-qr.png'), otpauthUri, { width: 300 }, (err) => {
        if (err) {
          log('Could not generate totp-qr.png:', err.message);
        } else {
          log('Wrote totp-qr.png -- scan with an authenticator app.');
        }
      });
    } catch (e) {
      log('qrcode package not installed; skipping QR generation (npm install to enable).');
    }
  }

  if (!fs.existsSync(CREDENTIALS_PATH) && !process.env.SITE_USERS_JSON) {
    writeCredentialsFile(secrets);
  }
}

main();
