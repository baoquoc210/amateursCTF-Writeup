import * as devalue from 'devalue';

const FLAG = 'FLAG{local_test_flag}';

class FlagRequest {
  constructor(feedback) {
    delete { feedback };
  }

  get flag() {
    if (this.admin) {
      return FLAG;
    } else {
      return 'haha nope';
    }
  }
}

function handle(body) {
  const flagRequest = devalue.parse(body, {
    FlagRequest: ([a]) => new FlagRequest(a),
  });

  if (!(flagRequest instanceof FlagRequest)) {
    console.log('not a flag request');
  } else {
    console.log('TYPE', Object.getPrototypeOf(flagRequest).constructor.name);
    console.log('ADMIN', flagRequest.admin);
    console.log('FLAG', flagRequest.flag);
  }
}

if (process.argv[2]) {
  handle(process.argv[2]);
}
