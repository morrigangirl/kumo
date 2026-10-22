// Copyright 2026 Kumo authors. All rights reserved.
import {sendWithPromise} from 'chrome://resources/js/cr.js';

export type KumoStatus = {[key: string]: unknown};
export type KumoParameters = {[key: string]: unknown};

export class KumoBrowserProxy {
  getStatus(): Promise<KumoStatus> {
    return sendWithPromise('kumoGetStatus');
  }

  performAction(operation: string, parameters: KumoParameters = {}): Promise<KumoStatus> {
    return sendWithPromise('kumoPerformAction', operation, parameters);
  }
}
