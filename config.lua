--
-- ~/.imapfilter/config.lua
--
-- For more info see http://blog.kylemanna.com/linux/2013/06/09/use-imapfilter-to-filter-spam-part2/
--
require("os")
require("io")
require("posix")

-- Update path for imapfilter relative files
package.path = package.path .. ';' .. '/home/spamfilter/.imapfilter/?.lua'
require("lua-popen3/pipe")

--
-- Trim whitespace from strings
--
function trim(s)
	return (s:gsub("^%s*(.-)%s*$", "%1"))
end

--
-- Filter the results through spamassassin
--
function filter(results)
	local mailbox
	local uid = {}
	local orig = {}
	local subresult_cnt = 32 -- Number of messages to process in each pass
	local max_procs = 10 -- Number of spamassasin processes to run in parallel

	for subresults, msgs in iter_msgs(results, subresult_cnt) do

		-- Filter it through spamassassin, avoid spamc due to localized
		-- user_perfs and bayes stores owned by this user.  This results
		-- in a minor performance hit (latency) when compared to spamd+spamc.
		local status, allmsg = pipe_multi(msgs, max_procs, 'spamassassin')

		for _, msg in pairs(allmsg) do
			-- TODO Why doesn't the following work?
			--pattern = "^X-Spam-Flag:\\s*YES"
			local pattern = 'X-Spam-Flag:\\s*YES'
			local match = regex_search(pattern, msg)
			local pattern = 'X-Spam-Status: No, score=(-?\\d+\\.\\d+)'
			local match2,value = regex_search(pattern, msg)


			local result = 'SPAM'
			if match == true then
				account1.Spam:append_message(msg)
                        elseif match2 == true then
                                local out = '>> value:  ' .. value .. '\n'
                                io.write(out)
				if tonumber(value) > 4.0 then
                                     result = 'Suspicious'
                                     account1.SpamSuspicion:append_message(msg)
                                else
				     result = 'normal'
				     account1.INBOX:append_message(msg)
                                end
			else
				result = 'normal'
				account1.INBOX:append_message(msg)
			end

			pattern = 'Subject:\\s*(.*)\\r\\n'
			match3, subject = regex_search(pattern, msg)
			if match3 == false then
				subject = '(unknown)'
			end
			io.write('>> Msg "' .. subject .. '" is ' .. result .. '\n')
                        --for some reason the new .. start at the beginning of the line again; OK, got it: windows line ending: \r\n
                        --io.write('>> TT "' .. subject .. '"\n')
		end

		-- Make old messages as seen and keep them
		-- Later we might delete them after we trust this filter
		subresults:mark_seen()
	end
end

--
-- Split up a large imapfilter result into chunk sizes
-- by iterating over it. Provides a way to elegantly
-- handle large results without blowing up memory
--
function iter_msgs(results, chunk)

	local i = 1
	local last = 0
	local max = #results

	return function()
		local subresults = {}
		local msgs = {}
		while i <= (last + chunk) and i <= max do
			local mailbox, uid = table.unpack(results[i])
			local mbox = mailbox[uid]
			local msg = mbox:fetch_message()
			table.insert(msgs, msg)
			table.insert(subresults, results[i])
			i = i + 1
		end
		last = i
		if next(subresults) then
			return Set(subresults), msgs
		end
	end
end

--
-- Feed spam messages to sa-learn to teach the bayesian classifier
--
function sa_learn(learn_type, results, dest)
	local learn_arg = '--' .. learn_type
	local subresult_cnt = 32 -- Number of messages to process in each pass
	local max_procs = 1 -- Number of sa-learn processes to run in parallel

	for subresults, msgs in iter_msgs(results, subresult_cnt) do
		local status = pipe_multi(msgs, max_procs, 'sa-learn', learn_arg)

		--[[
		for s in ipairs(status) do
			io.write('>> sa-learn returned '..s..'\n')
		end
		--]]
		subresults:move_messages(dest)
	end
end

--
-- Report spam messages to hash sharing and teach the bayesian classifier
--
function report_learn(learn_type, results, dest)
	local learn_arg = learn_type
	local subresult_cnt = 32 -- Number of messages to process in each pass
	local max_procs = 1 -- Number of sa-learn processes to run in parallel

	for subresults, msgs in iter_msgs(results, subresult_cnt) do
		local status = pipe_multi(msgs, max_procs, 'spamassassin', learn_arg)
		subresults:move_messages(dest)
	end
end

--
-- Sleep timer
--
function sleep(n)
  os.execute("sleep " .. tonumber(n))
end


--
-- Run in an infinite loop
--
function forever()

	--max_filter_size = 1024 * 1024 -- 1024 KB
	max_filter_size = 512000 -- 1024 KB
        --prevent to quick respawning
        sleep(10)

	account1:create_mailbox('Spam')
	account1:create_mailbox('SpamSuspicion')
	account1:create_mailbox('Spam/False Positives')
	account1:create_mailbox('Spam/False Negatives')
	account1:create_mailbox('Spam/False Positives/Processed')
	account1:create_mailbox('Spam/False Negatives/Processed')

	local unfiltered = account1['Unfiltered']
	local spam = account1['Spam']
	local false_pos = account1['Spam/False Positives']
	local false_pos_done = account1['Spam/False Positives/Processed']
	local false_neg = account1['Spam/False Negatives']
	local false_neg_done = account1['Spam/False Negatives/Processed']

	while true do

		-- Loop over the results in the event a new message shows up
		-- while we are proccessing earlier ones.
		local unseen = unfiltered:is_unseen()

		-- Just move the large messages
		local large = unfiltered:is_larger(max_filter_size)
		local results = unseen * large
		results:copy_messages(account1.INBOX)
		results:mark_seen()

		-- Filter the remaining messages
		local results = unseen - large
		filter(results)


		--
		-- House keeping... Other work to do?
		--

		-- Check for messages older then x days in the original inbox
		-- and delete them
		results = unfiltered:is_older(14):delete_messages()
		results = spam:is_older(60):delete_messages()

		-- Teach spamassassin about the good email that was marked as spam
		results = false_pos:is_smaller(max_filter_size)
		sa_learn('ham', results, false_pos_done)

		-- Teach spamassassin about the messages it missed
		results = false_neg:is_smaller(max_filter_size)
		--sa_learn('spam', results, false_neg_done)
                report_learn('-r', results, false_neg_done)

		-- Block until something happens, assuming server supports IMAP IDLE
		-- Note: there is still a window between checking unseen messages
		-- and entering idle where we could miss a new arrival.  In that
		-- case it will have to wait until another email arrives.
		if #unfiltered:is_unseen() == 0 then
			local update = unfiltered:enter_idle()

			-- Sleep 60 seconds if IDLE isn't supported
			if update == false then
				posix.sleep(60)
			end
		end
	end
end


---------------
--  Options  --
---------------

options.timeout = 120
options.keepalive = 5
--options.subscribe = true


----------------
--  Accounts  --
----------------
-- include ~/.imapfilter/accounts.lua (assuming package.path is set correctly)
require("accounts")


forever()

