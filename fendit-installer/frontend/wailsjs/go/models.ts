export namespace main {
	
	export class ActivationResult {
	    success: boolean;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ActivationResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.error = source["error"];
	    }
	}

}

