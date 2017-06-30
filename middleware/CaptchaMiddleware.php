<?php namespace Alxy\Captcha\Middleware;

use Flash;
use Closure;
use Session;
use ReCaptcha\ReCaptcha;
use Alxy\Captcha\Models\Settings;
use October\Rain\Exception\AjaxException;

class CaptchaMiddleware {

    /**
     * Run the request filter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if ($request->exists('g-recaptcha-response'))
        {
            $recaptcha = new ReCaptcha( Settings::get('secret_key') );

            /**
             * Verify the reponse, pass user's IP address
             */
            $response = $recaptcha->verify(
                $request->input('g-recaptcha-response'),
                $request->ip()
            );

            /**
             * Fail, if the response isn't OK
             */
            if (! $response->isSuccess() && count($response->getErrorCodes())) {
                if ($request->ajax()) {
                    throw new AjaxException( $response->getErrorCodes() );
                } else {
                    foreach ($response->getErrorCodes() as $code) {
                        Flash::error( $code );
                    }

                    return redirect()->back()->withInput();                  
                }  
            }

            Session::set("isHuman",true);

        }

        /**
         * Handle request
         */
        return $next($request);
    }

}
