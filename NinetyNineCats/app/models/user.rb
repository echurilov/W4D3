# == Schema Information
#
# Table name: users
#
#  id              :bigint(8)        not null, primary key
#  password_digest :string           not null
#  session_token   :string           not null
#  username        :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#

class User < ApplicationRecord
  validates :password, length: {minimum: 6, allow_nil: true}
  validates :session_token, :username, presence: true, uniqueness: true
  validates :password_digest, presence: true
  
  after_initialize :ensure_session_token
  
  attr_reader :password
  
  has_many :owned_cats,
    primary_key: :id,
    foreign_key: :user_id,
    class_name: :Cat
    
    has_many :rental_requests,
    foreign_key: :requester_id,
    class_name: :CatRentalRequest  
  
  def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    user && user.is_password?(password) ? user : nil
  end
  
  def ensure_session_token
    self.session_token ||= SecureRandom.urlsafe_base64
  end
  
  def reset_session_token!
    self.session_token = SecureRandom.urlsafe_base64
    self.save!
    self.session_token
  end
  
  def password=(pw)
    @password = pw
    self.password_digest = BCrypt::Password.create(pw)
  end
  
  def is_password?(pw)
    BCrypt::Password.new(self.password_digest).is_password?(pw)
  end
  
end
