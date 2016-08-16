Meteor.methods
	createOrUpdateTempUser: (userData) ->
		if not Meteor.userId()
			throw new Meteor.Error('error-invalid-user', 'Invalid user', { method: 'createOrUpdateTempUser' })

		user = Meteor.user()

		canEditTempUser = RocketChat.authz.hasPermission( user._id, 'edit-other-temp-user-info')
		canAddTempUser = RocketChat.authz.hasPermission( user._id, 'create-temp-user')
		
		# canEditUser = RocketChat.authz.hasPermission( user._id, 'edit-other-user-info')
		# canAddUser = RocketChat.authz.hasPermission( user._id, 'create-user')

		if userData._id and user._id isnt userData._id and canEditTempUser isnt true
			throw new Meteor.Error 'error-action-not-allowed', 'Editing temp user is not allowed', { method: 'createOrUpdateTempUser', action: 'Editing_user' }

		if not userData._id and canAddTempUser isnt true
			throw new Meteor.Error 'error-action-not-allowed', 'Adding temp user is not allowed', { method: 'createOrUpdateTempUser', action: 'Adding_user' }

		unless s.trim(userData.name)
			throw new Meteor.Error 'error-the-field-is-required', 'The field Name is required', { method: 'createOrUpdateTempUser', field: 'Name' }

		unless s.trim(userData.username)
			throw new Meteor.Error 'error-the-field-is-required', 'The field Username is required', { method: 'createOrUpdateTempUser', field: 'Username' }

		try
			nameValidation = new RegExp '^' + RocketChat.settings.get('UTF8_Names_Validation') + '$'
		catch
			nameValidation = new RegExp '^[@0-9a-zA-Z-_.]+$'

		if not nameValidation.test userData.username
			throw new Meteor.Error 'error-input-is-not-a-valid-field', "#{userData.username} is not a valid username", { method: 'createOrUpdateTempUser', input: userData.username, field: 'Username' }

		# if not userData._id and not userData.password
		# 	throw new Meteor.Error 'error-the-field-is-required', 'The field Password is required', { method: 'insertOrUpdateUser', field: 'Password' }

		if not userData._id
			if not RocketChat.checkUsernameAvailability userData.username
				throw new Meteor.Error 'error-field-unavailable', "#{userData.username} is already in use :(", { method: 'createOrUpdateTempUser', field: userData.username }

			if userData.email and not RocketChat.checkEmailAvailability userData.email
				throw new Meteor.Error 'error-field-unavailable', "#{userData.email} is already in use :(", { method: 'createOrUpdateTempUser', field: userData.email }

			RocketChat.validateEmailDomain(userData.email);

			# insert user
			createUser = { username: userData.username, password: "temp_user" }
			if userData.email
				createUser.email = userData.email

			_id = Accounts.createUser(createUser)

			updateUser =
				$set:
					name: userData.name

# 			if userData.requirePasswordChange
# 				updateUser.$set.requirePasswordChange = userData.requirePasswordChange
# 
# 			if userData.verified
# 				updateUser.$set['emails.0.verified'] = true

			Meteor.users.update { _id: _id }, updateUser

			Meteor.runAsUser _id, ->
				Meteor.call('joinDefaultChannels');
				
			return _id
		else
			#update user
			updateUser = {
				$set: {
					name: userData.name
				}
			}
			# if userData.verified
			# 	updateUser.$set['emails.0.verified'] = true
			# else
			# 	updateUser.$set['emails.0.verified'] = false

			Meteor.users.update { _id: userData._id }, updateUser
			RocketChat.setUsername userData._id, userData.username
			RocketChat.setEmail userData._id, userData.email

			# canEditUserPassword = RocketChat.authz.hasPermission( user._id, 'edit-other-user-password')
			# if canEditUserPassword and userData.password.trim()
			# 	Accounts.setPassword userData._id, userData.password.trim()

			return true
