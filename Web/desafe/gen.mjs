import * as devalue from 'devalue';

function show(label, value, reducers) {
  const s = devalue.stringify(value, reducers);
  console.log('---', label, '---');
  console.log(s);
}

show('plain object', {a: 1, b: 'x'});
show('array', [1,2,3]);
show('flagreq_default', {kind: 'FlagRequest', feedback: 'hi'});

// Example with custom reducer labelled "FlagRequest"
class Dummy {}
const obj = { feedback: 'hi', admin: true };
show('custom FlagRequest', obj, {
  FlagRequest: (value) => {
    if (value === obj) return ['arg', { admin: true }];
    return undefined;
  }
});
