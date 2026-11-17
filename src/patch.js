// Minimal JSON Patch (RFC 6902) and strategic-merge-patch implementation.
// Only the subset needed by admission policies is supported.

function parseJsonPointer(pointer) {
  if (pointer === '') return [];
  if (pointer[0] !== '/') {
    throw new Error(`Invalid JSON pointer: ${pointer}`);
  }
  return pointer
    .split('/')
    .slice(1)
    .map((segment) => segment.replace(/~1/g, '/').replace(/~0/g, '~'));
}

function isIndex(token) {
  return /^(0|[1-9][0-9]*)$/.test(token) || token === '-';
}

// Walk every segment except the last one, auto-vivifying missing containers
// so that mutation policies can create securityContext / capabilities trees.
function navigateForWrite(root, tokens) {
  let parent = root;
  for (let i = 0; i < tokens.length - 1; i += 1) {
    const token = tokens[i];
    const nextToken = tokens[i + 1];
    if (Array.isArray(parent)) {
      const index = token === '-' ? parent.length : Number(token);
      if (parent[index] === undefined || parent[index] === null) {
        parent[index] = isIndex(nextToken) ? [] : {};
      }
      parent = parent[index];
    } else {
      if (parent[token] === undefined || parent[token] === null) {
        parent[token] = isIndex(nextToken) ? [] : {};
      }
      parent = parent[token];
    }
  }
  return parent;
}

function applyJsonPatchOperation(document, operation) {
  const tokens = parseJsonPointer(operation.path);
  const leaf = tokens.length === 0 ? null : navigateForWrite(document, tokens);
  const key = tokens[tokens.length - 1];

  switch (operation.op) {
    case 'add': {
      if (tokens.length === 0) {
        document = operation.value;
      } else if (Array.isArray(leaf)) {
        const index = key === '-' ? leaf.length : Number(key);
        leaf.splice(index, 0, operation.value);
      } else {
        leaf[key] = operation.value;
      }
      break;
    }
    case 'replace': {
      if (tokens.length === 0) {
        document = operation.value;
      } else if (Array.isArray(leaf)) {
        leaf[Number(key)] = operation.value;
      } else {
        leaf[key] = operation.value;
      }
      break;
    }
    case 'remove': {
      if (tokens.length === 0) {
        document = null;
      } else if (Array.isArray(leaf)) {
        leaf.splice(Number(key), 1);
      } else {
        delete leaf[key];
      }
      break;
    }
    case 'test':
      if (JSON.stringify(tokens.length === 0 ? document : readPointer(document, tokens)) !== JSON.stringify(operation.value)) {
        throw new Error(`JSON patch test failed at ${operation.path}`);
      }
      break;
    case 'copy': {
      const value = readPointer(document, parseJsonPointer(operation.from));
      applyJsonPatchOperation(document, { op: 'add', path: operation.path, value });
      break;
    }
    case 'move': {
      const value = readPointer(document, parseJsonPointer(operation.from));
      applyJsonPatchOperation(document, { op: 'remove', path: operation.from });
      applyJsonPatchOperation(document, { op: 'add', path: operation.path, value });
      break;
    }
    default:
      throw new Error(`Unsupported JSON patch op: ${operation.op}`);
  }
  return document;
}

function readPointer(root, tokens) {
  let current = root;
  for (const token of tokens) {
    current = Array.isArray(current) ? current[Number(token)] : current[token];
  }
  return current;
}

// Apply a list of RFC 6902 operations in order, mutating and returning the doc.
export function applyJsonPatch(document, operations) {
  let working = document;
  for (const operation of operations) {
    working = applyJsonPatchOperation(working, operation);
  }
  return working;
}

const STRATEGIC_MERGE_KEYS = new Set([
  'hostNetwork',
  'hostPID',
  'hostIPC',
  'securityContext',
  'volumes',
  'containers',
  'initContainers',
  'ephemeralContainers',
]);

function strategicMergeArrays(base, patch) {
  // pod-spec arrays use name-based (strategic) merge semantics here.
  const merged = base.map((item) => ({ ...item }));
  for (const patchItem of patch) {
    if (patchItem === null) continue;
    const index = merged.findIndex(
      (item) => item && typeof item === 'object' && item.name === patchItem.name,
    );
    if (index === -1) {
      merged.push(patchItem);
    } else {
      merged[index] = strategicMergeValue(merged[index], patchItem);
    }
  }
  return merged;
}

function strategicMergeValue(base, patch) {
  if (patch === null) return null;
  if (Array.isArray(patch)) {
    return Array.isArray(base) ? strategicMergeArrays(base, patch) : patch.map((item) => item);
  }
  if (typeof patch !== 'object') return patch;
  const result = { ...(base && typeof base === 'object' && !Array.isArray(base) ? base : {}) };
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) {
      delete result[key];
    } else if (STRATEGIC_MERGE_KEYS.has(key) && typeof value === 'object') {
      result[key] = strategicMergeValue(result[key], value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

// Apply a strategic merge patch against the pod-spec subtree of a document.
// `base` is typically spec or the whole pod object.
export function applyStrategicMergePatch(document, patch) {
  return strategicMergeValue(document, patch);
}

// Detect whether a user-supplied patch looks like a JSON Patch array.
export function isJsonPatch(patch) {
  return (
    Array.isArray(patch) &&
    patch.every((operation) => operation && typeof operation === 'object' && 'op' in operation && 'path' in operation)
  );
}

export function applyPatch(document, patch) {
  if (patch === undefined || patch === null) return document;
  if (isJsonPatch(patch)) return applyJsonPatch(document, patch);
  return applyStrategicMergePatch(document, patch);
}
