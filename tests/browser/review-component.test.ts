import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { App, createReviewState, reviewReducer, sampleReview } from '../../apps/review/src/App.js';

test('sample review renders semantic table, named actions and honest sample limits', () => {
  const html = renderToStaticMarkup(createElement(App));
  assert.match(html, /Design preview · sample data/);
  assert.match(html, /<table/);
  assert.match(html, /OpenAI · project service key/);
  assert.match(html, /Demo hosting · API key/);
  assert.match(html, /Local integration · OAuth grant/);
  assert.match(html, /aria-pressed="false"/);
  assert.match(html, /Review on phone/);
  assert.match(html, /Inspect change details/);
  assert.doesNotMatch(html, /approved successfully|rotation succeeded/i);
});

test('drawer navigation and cancel/reset preserve selection without reporting credential results', () => {
  let state = createReviewState(sampleReview);
  state = reviewReducer(state, { type: 'select', id: 'openai-api' });
  assert.equal(state.drawer, 'credential');
  assert.equal(state.selectedId, 'openai-api');
  state = reviewReducer(state, { type: 'open', drawer: 'batch' });
  assert.equal(state.draft, 'reviewing');
  state = reviewReducer(state, { type: 'open', drawer: 'operation' });
  assert.equal(state.draft, 'reviewing');
  state = reviewReducer(state, { type: 'cancel' });
  assert.equal(state.drawer, null);
  assert.equal(state.draft, 'none');
  assert.equal(state.selectedId, 'openai-api');
  state = reviewReducer(state, { type: 'reset', review: sampleReview });
  assert.equal(state.selectedId, sampleReview.credentials[0]?.id);
});

test('system-following segmented appearance marks the resolved theme active', async () => {
  const { AppearanceControls } = await import('../../apps/review/src/App.js');
  for (const theme of ['light', 'dark'] as const) {
    const html = renderToStaticMarkup(createElement(AppearanceControls, { choice: 'system', theme, choose: () => undefined }));
    const buttons = [...html.matchAll(/<button aria-pressed="(true|false)"[^>]*>[\s\S]*?<\/button>/g)];
    assert.equal(buttons.length, 2);
    assert.equal(buttons[0]?.[1], theme === 'light' ? 'true' : 'false');
    assert.equal(buttons[1]?.[1], theme === 'dark' ? 'true' : 'false');
  }
});
