import * as fs from 'fs';
import * as yaml from 'js-yaml';

export class Helper {
  public static loadFile(filename: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      fs.readFile(filename, 'utf8', (err, contents) => {
        if (err) {
          reject(err);
        } else {
          resolve(contents);
        }
      });
    });
  }

  public static fromYAML(o: string, filename: string = 'yaml file'): any {
    return yaml.safeLoad(o, {
      filename: filename,
      onWarning: message => {},
      schema: yaml.DEFAULT_FULL_SCHEMA
    });
  }

  public static toYAML(o: any): string {
    return yaml.safeDump(o);
  }
}
