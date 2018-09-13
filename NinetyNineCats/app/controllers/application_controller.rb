class ApplicationController < ActionController::Base
# protect_from_forgery with: :exception
  helper_method :current_user, :logged_in?, :valid_owner?
  
  def current_user
    @current_user ||= User.find_by(session_token: session[:session_token])
  end
  
  def login!(user)
    @current_user = user
    session[:session_token] = user.reset_session_token!
  end
  
  def logout!
    current_user.reset_session_token!
    session[:session_token] = nil
    @current_user = nil
  end
  
  def require_login
    redirect_to new_session_url unless logged_in?
  end
  
  def require_logout
    redirect_to cats_url if logged_in?
  end
  
  def logged_in?
    !!self.current_user
  end
  
  def valid_owner?
    current_user.owned_cats.include?(params[:id])
  end
end
