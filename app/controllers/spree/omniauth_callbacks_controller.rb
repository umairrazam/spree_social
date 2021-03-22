class Spree::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  include Spree::Core::ControllerHelpers::Common
  include Spree::Core::ControllerHelpers::Order
  include Spree::Core::ControllerHelpers::Auth
  include Spree::Core::ControllerHelpers::Store

  def self.provides_callback_for(*providers)
    providers.each do |provider|
      class_eval <<-FUNCTION_DEFS, __FILE__, __LINE__ + 1
        def #{provider}
          kind_name = auth_hash['provider'] == "google_oauth2" ? "google" : auth_hash['provider']
          if request.env['omniauth.error'].present?
            flash[:error] = I18n.t('devise.omniauth_callbacks.failure', kind: kind_name, reason: Spree.t(:user_was_not_valid))
            redirect_back_or_default(root_url)
            return
          end

          authentication = Spree::UserAuthentication.find_by_provider_and_uid(kind_name, auth_hash['uid'])

          create_missing_authentication(kind_name,auth_hash['uid']) if (authentication.nil? && check_if_provider_missed_authentication(kind_name))
          if authentication.present? and authentication.try(:user).present?
            flash[:notice] = I18n.t('devise.omniauth_callbacks.success', kind: kind_name)
            sign_in_and_redirect :spree_user, authentication.user
          elsif spree_current_user
            spree_current_user.apply_omniauth(auth_hash)
            spree_current_user.save!
            flash[:notice] = I18n.t('devise.sessions.signed_in')
            redirect_back_or_default(account_url)
          else
            user = Spree::User.find_by_email(auth_hash['info']['email']) || Spree::User.new
            user.email                  =   auth_hash['info']['email'] rescue ""
            user.password               =   "dummyPassword12345678."  
            user.password_confirmation  =   "dummyPassword12345678."  
            user.first_name             =   user.email.split("@")[0] rescue ""
            if user.save(validate: false) 
              flash[:notice] = I18n.t('devise.omniauth_callbacks.success', kind: kind_name)
              sign_in_and_redirect :spree_user, user
            else
              session[:omniauth] = auth_hash.except('extra')
              flash[:notice] = Spree.t(:one_more_step, kind: kind_name.capitalize)
              redirect_to new_spree_user_registration_url
              return
            end
          end
        end
      FUNCTION_DEFS
    end
  end

  SpreeSocial::OAUTH_PROVIDERS.each do |provider|
    provides_callback_for provider[1].to_sym
  end

  def failure
    set_flash_message :alert, :failure, kind: failed_strategy.name.to_s.humanize, reason: failure_message
    redirect_to spree.login_path
  end

  def passthru
    render file: "#{Rails.root}/public/404", formats: [:html], status: 404, layout: false
  end

  def auth_hash
    request.env['omniauth.auth']
  end

  def create_missing_authentication(provider,uid)

    if provider.present? && uid.present?
      user_obj = {
        email:                  "john-smith#{uid}@gmail.com",
        password:               "dummyPassword12345678.",
        password_confirmation:  "dummyPassword12345678.",
        first_name: uid
      }
      user = Spree::User.new
      user.attributes = user_obj
      user.skip_confirmation!
      if user.save(validate: false)
        new_authentication_obj = {
          provider: provider,
          uid: uid,
          user: user
        }
        authentication = Spree::UserAuthentication.new(new_authentication_obj)
        authentication.save
      end
    end

  end

  def check_if_provider_missed_authentication(provider)
    ['instagram'].include?(provider)
  end

end
