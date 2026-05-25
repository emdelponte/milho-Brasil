import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // 1. Get the authorization header to verify the caller
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: 'Cabeçalho de autorização ausente.' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // 2. Initialize Supabase client with the service role key
    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? ''
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    
    if (!supabaseUrl || !supabaseServiceKey) {
      return new Response(
        JSON.stringify({ error: 'Configuração do servidor Supabase incompleta.' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      }
    })

    // 3. Verify the caller's JWT token
    const token = authHeader.replace('Bearer ', '')
    const { data: { user }, error: userError } = await supabaseAdmin.auth.getUser(token)

    if (userError || !user) {
      return new Response(
        JSON.stringify({ error: 'Não autorizado: Token inválido ou expirado.' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // 4. Verify if the caller is an authorized administrator
    const defaultAdmins = ['edelponte@gmail.com']
    const adminEmailsEnv = Deno.env.get('ADMIN_EMAILS')
    const allowedAdmins = adminEmailsEnv
      ? adminEmailsEnv.split(',').map(e => e.trim().toLowerCase())
      : defaultAdmins

    const callerEmail = user.email?.toLowerCase() || ''
    const isCallerAdmin = allowedAdmins.includes(callerEmail) || 
                          user.user_metadata?.role === 'admin' || 
                          user.user_metadata?.is_admin === true

    if (!isCallerAdmin) {
      return new Response(
        JSON.stringify({ error: `Acesso negado: O usuário ${callerEmail} não é um administrador autorizado.` }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // 5. Read the action requested
    const body = await req.json()
    const action = body.action || 'create' // Default action to maintain compatibility

    // LIST ACTION
    if (action === 'list') {
      const { data: { users }, error: listError } = await supabaseAdmin.auth.admin.listUsers()
      
      if (listError) {
        return new Response(
          JSON.stringify({ error: listError.message }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      // Map users to clean objects to return to the frontend
      const mappedUsers = users.map(u => ({
        id: u.id,
        email: u.email,
        nome_observador: u.user_metadata?.nome_observador || '',
        created_at: u.created_at,
        last_sign_in_at: u.last_sign_in_at
      }))

      return new Response(
        JSON.stringify({ users: mappedUsers }),
        { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // CREATE ACTION
    else if (action === 'create') {
      const { email, password, nome_observador } = body

      if (!email || !password) {
        return new Response(
          JSON.stringify({ error: 'E-mail e senha são obrigatórios para criar um novo usuário.' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      const { data: newUserData, error: createUserError } = await supabaseAdmin.auth.admin.createUser({
        email: email.trim(),
        password: password,
        email_confirm: true,
        user_metadata: {
          nome_observador: nome_observador?.trim() || ''
        }
      })

      if (createUserError) {
        return new Response(
          JSON.stringify({ error: createUserError.message }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      return new Response(
        JSON.stringify({ 
          message: 'Usuário criado com sucesso!', 
          user: {
            id: newUserData.user.id,
            email: newUserData.user.email,
            nome_observador: newUserData.user.user_metadata?.nome_observador || ''
          } 
        }),
        { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // UPDATE ACTION
    else if (action === 'update') {
      const { user_id, email, password, nome_observador } = body

      if (!user_id) {
        return new Response(
          JSON.stringify({ error: 'ID do usuário é obrigatório para atualização.' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      const updates: any = {
        user_metadata: {
          nome_observador: nome_observador?.trim() || ''
        }
      }
      if (email) updates.email = email.trim()
      // Only update password if provided
      if (password) updates.password = password

      const { data: updatedUserData, error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
        user_id,
        updates
      )

      if (updateError) {
        return new Response(
          JSON.stringify({ error: updateError.message }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      return new Response(
        JSON.stringify({ 
          message: 'Usuário atualizado com sucesso!', 
          user: {
            id: updatedUserData.user.id,
            email: updatedUserData.user.email,
            nome_observador: updatedUserData.user.user_metadata?.nome_observador || ''
          } 
        }),
        { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // DELETE ACTION
    else if (action === 'delete') {
      const { user_id } = body

      if (!user_id) {
        return new Response(
          JSON.stringify({ error: 'ID do usuário é obrigatório para exclusão.' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      // Check to prevent self-deletion
      if (user_id === user.id) {
        return new Response(
          JSON.stringify({ error: 'Você não pode excluir o seu próprio usuário administrador.' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(user_id)

      if (deleteError) {
        return new Response(
          JSON.stringify({ error: deleteError.message }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
      }

      return new Response(
        JSON.stringify({ message: 'Usuário excluído com sucesso!' }),
        { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // INVALID ACTION
    else {
      return new Response(
        JSON.stringify({ error: 'Ação solicitada inválida.' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})
