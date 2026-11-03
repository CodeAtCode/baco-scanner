# Vulnerable: SQL injection via user input
class Vulnerable
  def handle_request
    sql = params[:query]
    ActiveRecord::Base.connection.execute(sql)
  end
end
